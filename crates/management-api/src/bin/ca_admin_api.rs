//! Lab-only HTTP API for signed CA administration (ADR-0005 control plane,
//! ADR-0007 `trust-platform/ca-admin/v1`; both Proposed). LAB ONLY.
//!
//! The CA-admin counterpart of `revocation_api`, in its own process with
//! its own database login: separation of duties holds at the login, not
//! only at the token.
//! * `POST /v1/cas/{ca_id}/admin-change-challenges` (maker) with the change
//!   to propose (issuer registration, officer grant or removal, officer or
//!   admin credential enrolment or removal) returns a single-use challenge
//!   for the claim over its content digest.
//! * `POST /v1/admin-changes/{family}/{change_id}/approval-challenges` and
//!   `.../rejection-challenges` (another admin); `family` is `ca-admin`,
//!   `credential` or `admin-credential`.
//! * `POST /v1/admin-change-challenges/{challenge_id}/assertion` submits the
//!   authenticator's assertion; a proposal resends the change, which must be
//!   the signed one. `PgRevocationStore::submit_signed_admin` verifies the
//!   assertion before anything is written; the database re-checks the rest
//!   (migrations 0037, 0040, 0042).
//! * `GET /v1/cas/{ca_id}/pending-admin-changes` lists pending changes with
//!   their content and the digest a checker signs (migration 0044).
//! * `GET /v1/cas/{ca_id}/breakglass-uses` lists the CA's break-glass uses,
//!   and `POST /v1/breakglass-uses/{use_id}/review-challenges` issues a
//!   challenge for an admin's signed review of one (migration 0045), answered
//!   through the same assertion route. The emergency enrolment itself is
//!   not exposed over HTTP.
//!
//! The acting admin is the verified OIDC token's (issuer, subject), never a
//! request field (ADR-0003). The token must carry the `trust-ca-admin` role
//! and the CA in `ca_ids`; the database still requires the CA admin grant
//! and an enrolled admin key, and the CA must require signed administration
//! for the unsigned paths to be closed.
//!
//! The database login must hold only `trust_ca_admin` (`from_service_client`
//! refuses privileged logins). The connection follows the management API's
//! policy: TLS 1.3 verified against TRUST_DATABASE_CA_FILE by default;
//! plaintext only with TRUST_DATABASE_TLS=disable-lab (logged).
//! Environment: TRUST_OIDC_ISSUER, TRUST_OIDC_AUDIENCE,
//! TRUST_CA_ADMIN_DATABASE_URL, TRUST_DATABASE_TLS, TRUST_DATABASE_CA_FILE,
//! TRUST_WEBAUTHN_RP_ID, TRUST_WEBAUTHN_ORIGIN, TRUST_CA_ADMIN_BIND
//! (default 127.0.0.1:8084).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

// Shared with the read-only management API.
#[allow(dead_code)]
#[path = "../auth.rs"]
mod auth;
#[allow(dead_code)]
#[path = "../database.rs"]
mod database;
#[path = "../http_tls.rs"]
mod http_tls;
#[path = "../rate_limit.rs"]
mod rate_limit;
#[path = "../response_headers.rs"]
mod response_headers;

use auth::{Claims, OidcVerifier};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::{self, Write},
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;
use trust_pki_core::{
    officer_credential::CredentialChangeKind,
    revocation::OfficerIdentity,
    revocation_store::{
        AdminChallenge, AdminChange, AdminFamily, CredentialContent, OfficerGrantAction,
        PgRevocationStore, RevocationStoreError, SignedStep,
    },
    webauthn::{challenge_text, Assertion, RelyingParty},
};
use x509_cert::{der::Decode, Certificate};

const ADMIN_ROLE: &str = "trust-ca-admin";
const CHALLENGE_TTL_SECONDS: i32 = 300;
const MAX_CONCURRENT_REQUESTS: usize = 8;
/// Largest request body read (a registered issuer certificate is a few KiB).
const MAX_BODY_BYTES: usize = 64 * 1024;
const STATEMENT_TIMEOUT_MS: u64 = 5_000;

#[derive(Clone)]
struct AppState {
    verifier: OidcVerifier,
    store: Arc<Mutex<Option<PgRevocationStore>>>,
    database_url: Arc<String>,
    database_tls: database::DatabaseTls,
    rp_id: Arc<String>,
    origin: Arc<String>,
    slots: Arc<Semaphore>,
    limiter: Arc<rate_limit::RateLimiter>,
    /// Per client address, before the token is read (`limit_peers`).
    peers: Arc<rate_limit::RateLimiter>,
    /// The same identity's budget across replicas, in the database (0062).
    budget: rate_limit::SharedBudget,
}

/// The change an admin proposes, as JSON. Which fields apply depends on
/// `kind`; anything else present is refused.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ChangeRequest {
    kind: String,
    certificate_der: Option<String>,
    officer_issuer: Option<String>,
    officer_subject: Option<String>,
    credential_id: Option<String>,
    person_id: Option<String>,
    public_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionRequest {
    credential_id: String,
    authenticator_data: String,
    client_data_json: String,
    signature: String,
    change: Option<ChangeRequest>,
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge_id: String,
    change_id: Option<String>,
    webauthn_challenge: String,
    expires_at_us: i64,
}

/// A pending change as the checker reviews it (binary fields base64url).
#[derive(Serialize)]
struct PendingResponse {
    family: &'static str,
    change_id: String,
    kind: &'static str,
    certificate_der: Option<String>,
    officer_issuer: Option<String>,
    officer_subject: Option<String>,
    credential_id: Option<String>,
    person_id: Option<String>,
    public_key: Option<String>,
    content_sha256: String,
    maker_issuer: String,
    maker_subject: String,
    proposed_at_unix: i64,
    maker_signed: bool,
    /// Past the CA's maximum proposal age (0052): it can only be rejected.
    expired: bool,
    /// The maker's stored signature re-verifies in the Rust core.
    maker_evidence_verified: bool,
}

#[derive(Serialize)]
struct SubmittedResponse {
    change_id: String,
    /// For a break-glass review: whether the use now has its two reviews.
    #[serde(skip_serializing_if = "Option::is_none")]
    reviewed: Option<bool>,
}

/// What a break-glass use enrolled, re-verified (migration 0051).
#[derive(Serialize)]
struct BreakGlassDetailResponse {
    use_id: String,
    admin_credential_id: String,
    admin_issuer: String,
    admin_subject: String,
    person_id: String,
    public_key: String,
    evidence_verified: bool,
}

/// A break-glass use as admins review it (migration 0045).
#[derive(Serialize)]
struct BreakGlassUseResponse {
    use_id: String,
    admin_credential_id: String,
    admin_issuer: String,
    admin_subject: String,
    used_at_unix: i64,
    review_by_unix: i64,
    reviews: i64,
    reviewed: bool,
    overdue: bool,
}

/// A validated `ChangeRequest`: owned data an `AdminChange` borrows from.
struct OwnedChange {
    ca_id: String,
    kind: &'static str,
    certificate: Option<Certificate>,
    officer_issuer: String,
    officer_subject: String,
    credential_id: Vec<u8>,
    person_id: String,
    public_key: Vec<u8>,
}

impl OwnedChange {
    /// Field presence by kind; refused (400) before any database access.
    fn parse(ca_id: &str, request: &ChangeRequest) -> Result<Self, StatusCode> {
        let bad = || StatusCode::BAD_REQUEST;
        let decode = |field: &Option<String>| {
            field
                .as_deref()
                .ok_or(StatusCode::BAD_REQUEST)
                .and_then(|text| {
                    URL_SAFE_NO_PAD
                        .decode(text)
                        .map_err(|_| StatusCode::BAD_REQUEST)
                })
        };
        let (kind, credential) = match request.kind.as_str() {
            "REGISTER_ISSUER" => ("REGISTER_ISSUER", false),
            "GRANT_OFFICER" => ("GRANT_OFFICER", false),
            "REVOKE_OFFICER" => ("REVOKE_OFFICER", false),
            "ENROLL_CREDENTIAL" => ("ENROLL_CREDENTIAL", true),
            "REMOVE_CREDENTIAL" => ("REMOVE_CREDENTIAL", true),
            "ENROLL_ADMIN_CREDENTIAL" => ("ENROLL_ADMIN_CREDENTIAL", true),
            "REMOVE_ADMIN_CREDENTIAL" => ("REMOVE_ADMIN_CREDENTIAL", true),
            _ => return Err(bad()),
        };
        let mut change = Self {
            ca_id: ca_id.to_owned(),
            kind,
            certificate: None,
            officer_issuer: String::new(),
            officer_subject: String::new(),
            credential_id: Vec::new(),
            person_id: String::new(),
            public_key: Vec::new(),
        };
        if kind == "REGISTER_ISSUER" {
            if request.officer_issuer.is_some()
                || request.officer_subject.is_some()
                || request.credential_id.is_some()
                || request.person_id.is_some()
                || request.public_key.is_some()
            {
                return Err(bad());
            }
            let der = decode(&request.certificate_der)?;
            change.certificate = Some(Certificate::from_der(&der).map_err(|_| bad())?);
            return Ok(change);
        }
        if request.certificate_der.is_some() {
            return Err(bad());
        }
        change.officer_issuer = request.officer_issuer.clone().ok_or_else(bad)?;
        change.officer_subject = request.officer_subject.clone().ok_or_else(bad)?;
        if credential {
            change.credential_id = decode(&request.credential_id)?;
            change.person_id = request.person_id.clone().ok_or_else(bad)?;
            change.public_key = decode(&request.public_key)?;
        } else if request.credential_id.is_some()
            || request.person_id.is_some()
            || request.public_key.is_some()
        {
            return Err(bad());
        }
        Ok(change)
    }

    /// Runs `work` with the `AdminChange` view of this change.
    fn with<T>(&self, work: impl FnOnce(&AdminChange<'_>) -> T) -> Result<T, StatusCode> {
        let officer = OfficerIdentity {
            issuer: &self.officer_issuer,
            subject: &self.officer_subject,
        };
        let content = CredentialContent {
            ca_id: &self.ca_id,
            credential_id: &self.credential_id,
            officer: &officer,
            person_id: &self.person_id,
            public_key_sec1: &self.public_key,
        };
        let change = match self.kind {
            "REGISTER_ISSUER" => AdminChange::RegisterIssuer(
                self.certificate.as_ref().ok_or(StatusCode::BAD_REQUEST)?,
            ),
            "GRANT_OFFICER" => AdminChange::Officer(OfficerGrantAction::Grant, &officer),
            "REVOKE_OFFICER" => AdminChange::Officer(OfficerGrantAction::Revoke, &officer),
            "ENROLL_CREDENTIAL" => AdminChange::Credential(CredentialChangeKind::Enroll, &content),
            "REMOVE_CREDENTIAL" => AdminChange::Credential(CredentialChangeKind::Remove, &content),
            "ENROLL_ADMIN_CREDENTIAL" => {
                AdminChange::AdminCredential(CredentialChangeKind::Enroll, &content)
            }
            _ => AdminChange::AdminCredential(CredentialChangeKind::Remove, &content),
        };
        Ok(work(&change))
    }
}

fn write_log(value: serde_json::Value) {
    // Never log tokens, assertions or database errors.
    let _ = writeln!(io::stderr().lock(), "{value}");
}

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/cas/{ca_id}/admin-change-challenges",
            post(proposal_challenge),
        )
        .route(
            "/v1/admin-changes/{family}/{change_id}/approval-challenges",
            post(approval_challenge),
        )
        .route(
            "/v1/admin-changes/{family}/{change_id}/rejection-challenges",
            post(rejection_challenge),
        )
        .route(
            "/v1/admin-change-challenges/{challenge_id}/assertion",
            post(submit_assertion),
        )
        .route(
            "/v1/cas/{ca_id}/pending-admin-changes",
            get(pending_admin_changes),
        )
        .route("/v1/cas/{ca_id}/breakglass-uses", get(breakglass_uses))
        .route("/v1/breakglass-uses/{use_id}", get(breakglass_use))
        .route(
            "/v1/breakglass-uses/{use_id}/review-challenges",
            post(breakglass_review_challenge),
        )
        // Per client address, before the token is read.
        .layer(axum::middleware::from_fn_with_state(
            state.peers.clone(),
            rate_limit::limit_peers,
        ))
        .layer(axum::middleware::from_fn(
            response_headers::security_headers,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn canonical_uuid(text: &str) -> Option<String> {
    let uuid = uuid::Uuid::parse_str(text).ok()?;
    let canonical = uuid.hyphenated().to_string();
    (canonical == text).then_some(canonical)
}

fn hex_uuid(bytes: &[u8; 16]) -> String {
    uuid::Uuid::from_bytes(*bytes).hyphenated().to_string()
}

fn family_path(family: AdminFamily) -> &'static str {
    match family {
        AdminFamily::CaAdmin => "ca-admin",
        AdminFamily::Credential => "credential",
        AdminFamily::AdminCredential => "admin-credential",
    }
}

fn family(text: &str) -> Option<AdminFamily> {
    match text {
        "ca-admin" => Some(AdminFamily::CaAdmin),
        "credential" => Some(AdminFamily::Credential),
        "admin-credential" => Some(AdminFamily::AdminCredential),
        _ => None,
    }
}

async fn admin(headers: &HeaderMap, state: &AppState) -> Result<Claims, StatusCode> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = state
        .verifier
        .verify(token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !claims.roles.iter().any(|role| role == ADMIN_ROLE) {
        return Err(StatusCode::FORBIDDEN);
    }
    // Per-identity budget, before any database access.
    if !state.limiter.allow(&claims.iss, &claims.sub) {
        write_log(serde_json::json!({"event":"rate_limited"}));
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(claims)
}

/// Database refusals keep their meaning; anything else is unavailability.
fn status_of(error: &RevocationStoreError) -> StatusCode {
    match error {
        RevocationStoreError::Database(e) => match e.code().map(|c| c.code()) {
            Some("42501") => StatusCode::FORBIDDEN,
            Some("22023") => StatusCode::BAD_REQUEST,
            Some("23514" | "42704" | "55000") => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        },
        RevocationStoreError::InvalidAssertion(_)
        | RevocationStoreError::InvalidCredential(_)
        | RevocationStoreError::InvalidIssuer => StatusCode::BAD_REQUEST,
        RevocationStoreError::SignedApprovalRefused => StatusCode::CONFLICT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

enum Failure {
    Store(RevocationStoreError),
    Refused(StatusCode),
}

impl From<RevocationStoreError> for Failure {
    fn from(value: RevocationStoreError) -> Self {
        Self::Store(value)
    }
}

/// Runs `work` on the CA-admin session, reconnecting after a failure.
async fn with_store<T: Send + 'static>(
    state: &AppState,
    claims: &Claims,
    work: impl FnOnce(&mut PgRevocationStore) -> Result<T, Failure> + Send + 'static,
) -> Result<T, StatusCode> {
    let _permit = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let store = state.store.clone();
    let url = state.database_url.clone();
    let tls = state.database_tls.clone();
    let budget = state.budget;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    tokio::task::spawn_blocking(move || {
        let mut slot = store.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if slot.is_none() {
            let client = database::connect_client(&url, &tls, STATEMENT_TIMEOUT_MS)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            *slot = Some(
                PgRevocationStore::from_service_client(client)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
            );
        }
        let session = slot.as_mut().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        // The identity's budget across every replica (0062), before the
        // work; an error fails closed.
        match session.consume_api_budget(
            budget.scope,
            &issuer,
            &subject,
            budget.limit,
            budget.window_seconds,
        ) {
            Ok(true) => {}
            Ok(false) => {
                write_log(serde_json::json!({"event":"rate_limited_shared"}));
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            Err(error) => {
                if matches!(&error, RevocationStoreError::Database(e) if e.code().is_none()) {
                    *slot = None;
                }
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        }
        match work(session) {
            Ok(value) => Ok(value),
            Err(Failure::Refused(status)) => Err(status),
            Err(Failure::Store(error)) => {
                if matches!(&error, RevocationStoreError::Database(e) if e.code().is_none()) {
                    *slot = None;
                }
                Err(status_of(&error))
            }
        }
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
}

fn challenge_response(challenge_id: String, challenge: &AdminChallenge) -> Response {
    (
        StatusCode::CREATED,
        Json(ChallengeResponse {
            challenge_id,
            change_id: challenge.claim.change_id.as_ref().map(hex_uuid),
            webauthn_challenge: challenge_text(&challenge.claim.digest()),
            expires_at_us: challenge.claim.expires_at_us,
        }),
    )
        .into_response()
}

async fn proposal_challenge(
    State(state): State<AppState>,
    Path(ca_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ChangeRequest>,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state).await?;
    let ca_id = canonical_uuid(&ca_id).ok_or(StatusCode::NOT_FOUND)?;
    if !claims.ca_ids.contains(&ca_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let change = OwnedChange::parse(&ca_id, &request)?;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let (challenge_id, challenge) = with_store(&state, &claims, move |store| {
        let maker = OfficerIdentity {
            issuer: &issuer,
            subject: &subject,
        };
        let id = change
            .with(|change| {
                store.issue_admin_proposal_challenge(&ca_id, change, &maker, CHALLENGE_TTL_SECONDS)
            })
            .map_err(Failure::Refused)??;
        let challenge = store.admin_challenge(&id)?;
        Ok((id, challenge))
    })
    .await?;
    write_log(
        serde_json::json!({"event":"admin_change_challenge_issued","step":"propose",
                                 "challenge_id":challenge_id}),
    );
    Ok(challenge_response(challenge_id, &challenge))
}

/// Approval or rejection by another admin. The change's CA is checked
/// against the token's scope before anything is written (unknown 404, out
/// of scope 403, migration 0050); the database then checks the actor's
/// admin grant, and the issued challenge's CA is checked again.
async fn decision_challenge(
    state: AppState,
    family_text: String,
    change_id: String,
    headers: HeaderMap,
    step: SignedStep,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state).await?;
    let family = family(&family_text).ok_or(StatusCode::NOT_FOUND)?;
    let change_id = canonical_uuid(&change_id).ok_or(StatusCode::NOT_FOUND)?;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let ca_ids = claims.ca_ids.clone();
    let (rp_id, origin) = (state.rp_id.clone(), state.origin.clone());
    let (challenge_id, challenge) = with_store(&state, &claims, move |store| {
        let ca = store.admin_change_ca(family, &change_id)?;
        in_scope(ca.clone(), &ca_ids)?;
        // An expired proposal is no longer approvable (0052): refuse before
        // anyone signs; it can still be rejected.
        if step == SignedStep::Approve {
            if let Some(ca) = ca {
                if store
                    .stale_admin_proposals(&ca)?
                    .contains(&(family, change_id.clone()))
                {
                    return Err(Failure::Refused(StatusCode::CONFLICT));
                }
            }
            // Nobody signs an approval of a proposal whose stored maker
            // signature does not re-verify (the database cannot check it).
            let rp = RelyingParty {
                rp_id: &rp_id,
                origin: &origin,
            };
            if store
                .verify_pending_admin_maker(family, &change_id, &rp)
                .is_err()
            {
                write_log(serde_json::json!({"event":"maker_evidence_refused",
                                             "change_id":change_id}));
                return Err(Failure::Refused(StatusCode::CONFLICT));
            }
        }
        let checker = OfficerIdentity {
            issuer: &issuer,
            subject: &subject,
        };
        let id = if step == SignedStep::Reject {
            store.issue_admin_rejection_challenge(
                family,
                &change_id,
                &checker,
                CHALLENGE_TTL_SECONDS,
            )?
        } else {
            store.issue_admin_approval_challenge(
                family,
                &change_id,
                &checker,
                CHALLENGE_TTL_SECONDS,
            )?
        };
        let challenge = store.admin_challenge(&id)?;
        Ok((id, challenge))
    })
    .await?;
    if !claims.ca_ids.contains(&hex_uuid(&challenge.claim.ca_id)) {
        return Err(StatusCode::FORBIDDEN);
    }
    let step = if step == SignedStep::Reject {
        "reject"
    } else {
        "approve"
    };
    write_log(
        serde_json::json!({"event":"admin_change_challenge_issued","step":step,
                                 "challenge_id":challenge_id}),
    );
    Ok(challenge_response(challenge_id, &challenge))
}

/// Unknown (404) or outside the token's CAs (403), before any write.
fn in_scope(ca: Option<String>, ca_ids: &[String]) -> Result<(), Failure> {
    match ca {
        None => Err(Failure::Refused(StatusCode::NOT_FOUND)),
        Some(ca) if !ca_ids.contains(&ca) => Err(Failure::Refused(StatusCode::FORBIDDEN)),
        Some(_) => Ok(()),
    }
}

async fn approval_challenge(
    State(state): State<AppState>,
    Path((family, change_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    decision_challenge(state, family, change_id, headers, SignedStep::Approve).await
}

async fn rejection_challenge(
    State(state): State<AppState>,
    Path((family, change_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    decision_challenge(state, family, change_id, headers, SignedStep::Reject).await
}

/// The CA's pending CA-admin changes with their content and the digest a
/// checker signs (recomputed and checked by the Rust core, migration 0044).
async fn pending_admin_changes(
    State(state): State<AppState>,
    Path(ca_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state).await?;
    let ca_id = canonical_uuid(&ca_id).ok_or(StatusCode::NOT_FOUND)?;
    if !claims.ca_ids.contains(&ca_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let (rp_id, origin) = (state.rp_id.clone(), state.origin.clone());
    let pending = with_store(&state, &claims, move |store| {
        let rp = RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        };
        let changes = store.pending_admin_changes(&ca_id)?;
        Ok(changes
            .into_iter()
            .map(|change| {
                let verified = change.maker_signed
                    && store
                        .verify_pending_admin_maker(change.family, &change.change_id, &rp)
                        .is_ok();
                (change, verified)
            })
            .collect::<Vec<_>>())
    })
    .await?;
    let encode = |bytes: &Option<Vec<u8>>| bytes.as_ref().map(|b| URL_SAFE_NO_PAD.encode(b));
    let body: Vec<PendingResponse> = pending
        .into_iter()
        .map(|(change, maker_evidence_verified)| PendingResponse {
            family: family_path(change.family),
            kind: change.kind,
            certificate_der: encode(&change.certificate_der),
            credential_id: encode(&change.credential_id),
            public_key: encode(&change.public_key_sec1),
            content_sha256: URL_SAFE_NO_PAD.encode(change.content_sha256),
            change_id: change.change_id,
            officer_issuer: change.officer_issuer,
            officer_subject: change.officer_subject,
            person_id: change.person_id,
            maker_issuer: change.maker_issuer,
            maker_subject: change.maker_subject,
            proposed_at_unix: change.proposed_at_unix,
            maker_signed: change.maker_signed,
            expired: change.expired,
            maker_evidence_verified,
        })
        .collect();
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// The CA's break-glass uses, oldest first (migration 0045).
async fn breakglass_uses(
    State(state): State<AppState>,
    Path(ca_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state).await?;
    let ca_id = canonical_uuid(&ca_id).ok_or(StatusCode::NOT_FOUND)?;
    if !claims.ca_ids.contains(&ca_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let uses = with_store(&state, &claims, move |store| {
        Ok(store.breakglass_uses(&ca_id)?)
    })
    .await?;
    let body: Vec<BreakGlassUseResponse> = uses
        .into_iter()
        .map(|used| BreakGlassUseResponse {
            use_id: used.use_id,
            admin_credential_id: URL_SAFE_NO_PAD.encode(&used.admin_credential_id),
            admin_issuer: used.admin_issuer,
            admin_subject: used.admin_subject,
            used_at_unix: used.used_at_unix,
            review_by_unix: used.review_by_unix,
            reviews: used.reviews,
            reviewed: used.reviewed,
            overdue: used.overdue,
        })
        .collect();
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// What a break-glass use enrolled and whether its stored evidence
/// re-verifies in the Rust core (migration 0051).
async fn breakglass_use(
    State(state): State<AppState>,
    Path(use_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state).await?;
    let use_id = canonical_uuid(&use_id).ok_or(StatusCode::NOT_FOUND)?;
    let ca_ids = claims.ca_ids.clone();
    let (rp_id, origin) = (state.rp_id.clone(), state.origin.clone());
    let (content, verified) = with_store(&state, &claims, move |store| {
        in_scope(store.breakglass_use_ca(&use_id)?, &ca_ids)?;
        let rp = RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        };
        let (content, result) = store
            .breakglass_use_evidence(&use_id, &rp)?
            .ok_or(Failure::Refused(StatusCode::NOT_FOUND))?;
        Ok((content, result.is_ok()))
    })
    .await?;
    Ok((
        StatusCode::OK,
        Json(BreakGlassDetailResponse {
            use_id: content.use_id,
            admin_credential_id: URL_SAFE_NO_PAD.encode(&content.admin_credential_id),
            admin_issuer: content.admin_issuer,
            admin_subject: content.admin_subject,
            person_id: content.person_id,
            public_key: URL_SAFE_NO_PAD.encode(&content.public_key_sec1),
            evidence_verified: verified,
        }),
    )
        .into_response())
}

/// A review challenge for a break-glass use, for an admin other than the
/// one it enrolled. As for approvals, the use's CA is checked against the
/// token's scope before anything is written; the use's evidence must
/// re-verify in the Rust core (409 otherwise, migration 0051); then the
/// database checks the admin grant.
async fn breakglass_review_challenge(
    State(state): State<AppState>,
    Path(use_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state).await?;
    let use_id = canonical_uuid(&use_id).ok_or(StatusCode::NOT_FOUND)?;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let ca_ids = claims.ca_ids.clone();
    let (rp_id, origin) = (state.rp_id.clone(), state.origin.clone());
    let (challenge_id, challenge) = with_store(&state, &claims, move |store| {
        in_scope(store.breakglass_use_ca(&use_id)?, &ca_ids)?;
        // Nobody reviews a use whose evidence does not re-verify (0051).
        let rp = RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        };
        match store.breakglass_use_evidence(&use_id, &rp)? {
            None => return Err(Failure::Refused(StatusCode::NOT_FOUND)),
            Some((_, Err(_))) => {
                write_log(serde_json::json!({"event":"breakglass_evidence_refused",
                                             "use_id":use_id}));
                return Err(Failure::Refused(StatusCode::CONFLICT));
            }
            Some((_, Ok(()))) => {}
        }
        let reviewer = OfficerIdentity {
            issuer: &issuer,
            subject: &subject,
        };
        let id =
            store.issue_breakglass_review_challenge(&use_id, &reviewer, CHALLENGE_TTL_SECONDS)?;
        let challenge = store.admin_challenge(&id)?;
        Ok((id, challenge))
    })
    .await?;
    if !claims.ca_ids.contains(&hex_uuid(&challenge.claim.ca_id)) {
        return Err(StatusCode::FORBIDDEN);
    }
    write_log(
        serde_json::json!({"event":"admin_change_challenge_issued","step":"review",
                                 "challenge_id":challenge_id}),
    );
    Ok(challenge_response(challenge_id, &challenge))
}

async fn submit_assertion(
    State(state): State<AppState>,
    Path(challenge_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AssertionRequest>,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state).await?;
    let challenge_id = canonical_uuid(&challenge_id).ok_or(StatusCode::NOT_FOUND)?;
    let decode = |field: &str| {
        URL_SAFE_NO_PAD
            .decode(field)
            .map_err(|_| StatusCode::BAD_REQUEST)
    };
    let credential_id = decode(&request.credential_id)?;
    let authenticator_data = decode(&request.authenticator_data)?;
    let client_data_json = decode(&request.client_data_json)?;
    let signature = decode(&request.signature)?;
    let change_request = request.change;
    let (rp_id, origin) = (state.rp_id.clone(), state.origin.clone());
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let ca_ids = claims.ca_ids.clone();
    let result = with_store(&state, &claims, move |store| {
        let challenge = store.admin_challenge(&challenge_id)?;
        let ca = hex_uuid(&challenge.claim.ca_id);
        // Only the admin the challenge was issued to may answer it, and only
        // within the token's CA scope.
        if (
            challenge.actor_issuer.as_str(),
            challenge.actor_subject.as_str(),
        ) != (issuer.as_str(), subject.as_str())
            || !ca_ids.contains(&ca)
        {
            return Err(Failure::Refused(StatusCode::FORBIDDEN));
        }
        let change = match (challenge.purpose, &change_request) {
            (SignedStep::Propose, Some(request)) => {
                Some(OwnedChange::parse(&ca, request).map_err(Failure::Refused)?)
            }
            (SignedStep::Propose, None) | (_, Some(_)) => {
                return Err(Failure::Refused(StatusCode::BAD_REQUEST))
            }
            _ => None,
        };
        let assertion = Assertion {
            authenticator_data: &authenticator_data,
            client_data_json: &client_data_json,
            signature_der: &signature,
        };
        let rp = RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        };
        if challenge.purpose == SignedStep::Review {
            let reviewed =
                store.submit_breakglass_review(&challenge_id, &credential_id, &assertion, &rp)?;
            let use_id = challenge
                .claim
                .change_id
                .as_ref()
                .map(hex_uuid)
                .ok_or(Failure::Refused(StatusCode::SERVICE_UNAVAILABLE))?;
            return Ok((use_id, challenge.purpose, Some(reviewed)));
        }
        let id = match &change {
            Some(change) => change
                .with(|change| {
                    store.submit_signed_admin(
                        &challenge_id,
                        &credential_id,
                        &assertion,
                        &rp,
                        Some(change),
                    )
                })
                .map_err(Failure::Refused)??,
            None => {
                store.submit_signed_admin(&challenge_id, &credential_id, &assertion, &rp, None)?
            }
        };
        Ok((id, challenge.purpose, None))
    })
    .await;
    let (change_id, step, reviewed) = match result {
        Ok(done) => done,
        Err(status) => {
            write_log(serde_json::json!({"event":"admin_assertion_refused",
                                         "status":status.as_u16()}));
            return Err(status);
        }
    };
    let event = match step {
        SignedStep::Propose => "admin_change_proposed",
        SignedStep::Reject => "admin_change_rejected",
        SignedStep::Review => "breakglass_use_reviewed",
        _ => "admin_change_approved",
    };
    write_log(serde_json::json!({"event":event,"change_id":change_id}));
    Ok((
        StatusCode::OK,
        Json(SubmittedResponse {
            change_id,
            reviewed,
        }),
    )
        .into_response())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Transport policy first, so bad TLS settings fail before any connection.
    let http_tls = http_tls::from_env()?;
    if matches!(http_tls, http_tls::HttpTls::DisabledForLab) {
        write_log(serde_json::json!({"event":"ca_admin_http_tls_disabled_lab"}));
    }
    // Bound and checked before any OIDC or database work: a refused
    // transport fails fast.
    let bind = env::var("TRUST_CA_ADMIN_BIND").unwrap_or_else(|_| "127.0.0.1:8084".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    http_tls::check_bind(&http_tls, &listener)?;
    let issuer = env::var("TRUST_OIDC_ISSUER")?;
    let audience = env::var("TRUST_OIDC_AUDIENCE")?;
    let database_url = env::var("TRUST_CA_ADMIN_DATABASE_URL")?;
    let rp_id = env::var("TRUST_WEBAUTHN_RP_ID")?;
    let origin = env::var("TRUST_WEBAUTHN_ORIGIN")?;
    let database_tls = database::tls_from_settings(
        env::var(database::TLS_MODE_ENV).ok().as_deref(),
        env::var(database::CA_FILE_ENV).ok().as_deref(),
    )?;
    if matches!(database_tls, database::DatabaseTls::DisabledForLab) {
        write_log(serde_json::json!({"event":"ca_admin_database_tls_disabled_lab"}));
    }
    let (check_url, check_tls) = (database_url.clone(), database_tls.clone());
    let checked = tokio::task::spawn_blocking(move || {
        database::connect_client(&check_url, &check_tls, STATEMENT_TIMEOUT_MS)
            .map(PgRevocationStore::from_service_client)
    })
    .await?;
    match checked {
        Err(()) => return Err("CA admin database unavailable (connection or TLS failed)".into()),
        Ok(Err(RevocationStoreError::PrivilegedSession)) => {
            return Err("CA admin database login is privileged; use a CA admin login".into())
        }
        Ok(Err(_)) => return Err("CA admin database check failed".into()),
        Ok(Ok(_)) => {}
    }
    let verifier = OidcVerifier::discover(&issuer, &audience).await?;
    let state = AppState {
        verifier,
        store: Arc::new(Mutex::new(None)),
        database_url: Arc::new(database_url),
        database_tls,
        rp_id: Arc::new(rp_id),
        origin: Arc::new(origin),
        slots: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        limiter: Arc::new(rate_limit::RateLimiter::per_minute()),
        peers: Arc::new(rate_limit::RateLimiter::peers_per_minute()),
        budget: rate_limit::SharedBudget::per_minute("ca_admin"),
    };
    let tls = matches!(http_tls, http_tls::HttpTls::Enabled(_));
    write_log(serde_json::json!({"event":"ca_admin_api_started","bind":bind,"tls":tls}));
    http_tls::serve(listener, router(state), http_tls).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rsa::{
        pkcs8::{EncodePrivateKey, LineEnding},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    const ISSUER: &str = "https://issuer.example.test";
    const RP_ID: &str = "admin.lab.invalid";
    const ORIGIN: &str = "https://admin.lab.invalid";
    const CA: &str = "5eedc0de-0000-4000-8000-000000000044";

    struct Oidc {
        verifier: OidcVerifier,
        signer: EncodingKey,
    }

    fn oidc() -> Oidc {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"ca-admin-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        Oidc {
            verifier: OidcVerifier::from_jwks(ISSUER, "trust-api", jwks).unwrap(),
            signer: EncodingKey::from_rsa_pem(
                private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
            )
            .unwrap(),
        }
    }

    impl Oidc {
        fn token(&self, subject: &str, roles: &[&str], ca_ids: &[&str]) -> String {
            let mut header = Header::new(Algorithm::RS256);
            header.typ = Some("at+jwt".into());
            header.kid = Some("ca-admin-test".into());
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":ISSUER, "aud":"trust-api", "sub":subject, "nbf":now-1,
                        "exp":now+300, "roles":roles, "ca_ids":ca_ids}),
                &self.signer,
            )
            .unwrap()
        }
    }

    type Session = Arc<Mutex<Option<PgRevocationStore>>>;

    fn app_with_session(verifier: OidcVerifier, database_url: &str) -> (Router, Session) {
        let session: Session = Arc::new(Mutex::new(None));
        let router = router(AppState {
            verifier,
            store: session.clone(),
            database_url: Arc::new(database_url.to_owned()),
            database_tls: database::DatabaseTls::DisabledForLab,
            rp_id: Arc::new(RP_ID.into()),
            origin: Arc::new(ORIGIN.into()),
            slots: Arc::new(Semaphore::new(4)),
            limiter: Arc::new(rate_limit::RateLimiter::per_minute()),
            peers: Arc::new(rate_limit::RateLimiter::peers_per_minute()),
            budget: rate_limit::SharedBudget::per_minute("ca_admin"),
        });
        (router, session)
    }

    /// Counted per client address before the token is read (as in the
    /// revocation API).
    #[tokio::test]
    async fn requests_are_limited_per_client_address_before_authentication() {
        use axum::extract::connect_info::MockConnectInfo;
        use std::{net::SocketAddr, time::Duration};
        let router = router(AppState {
            verifier: oidc().verifier.clone(),
            store: Arc::new(Mutex::new(None)),
            database_url: Arc::new("postgresql://unused.invalid/none".into()),
            database_tls: database::DatabaseTls::DisabledForLab,
            rp_id: Arc::new(RP_ID.into()),
            origin: Arc::new(ORIGIN.into()),
            slots: Arc::new(Semaphore::new(4)),
            limiter: Arc::new(rate_limit::RateLimiter::per_minute()),
            peers: Arc::new(rate_limit::RateLimiter::new(2, Duration::from_secs(60))),
            budget: rate_limit::SharedBudget::per_minute("ca_admin"),
        });
        let from = |addr: &str| {
            let addr: SocketAddr = addr.parse().unwrap();
            router
                .clone()
                .layer(MockConnectInfo(rate_limit::ClientAddr(addr)))
        };
        let path = format!("/v1/cas/{CA}/pending-admin-changes");
        for _ in 0..2 {
            assert_eq!(
                get(&from("192.0.2.7:1"), &path, "not-a-token").await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            get(&from("192.0.2.7:2"), &path, "not-a-token").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            get(&from("198.51.100.9:1"), &path, "not-a-token").await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    async fn post(
        app: &Router,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::post(path).header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn get(app: &Router, path: &str, token: &str) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::get(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Refusals decided before any database access.
    #[tokio::test]
    async fn requests_are_authenticated_scoped_and_validated() {
        let oidc = oidc();
        let (app, _) = app_with_session(oidc.verifier.clone(), "postgresql://unused.invalid/none");
        let path = format!("/v1/cas/{CA}/admin-change-challenges");
        let grant = json!({"kind":"GRANT_OFFICER","officer_issuer":ISSUER,"officer_subject":"x"});
        assert_eq!(
            post(&app, &path, None, grant.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let officer = oidc.token("admin-a", &["trust-revocation-officer"], &[CA]);
        assert_eq!(
            post(&app, &path, Some(&officer), grant.clone()).await.0,
            StatusCode::FORBIDDEN
        );
        let other_ca = oidc.token(
            "admin-a",
            &[ADMIN_ROLE],
            &["5eedc0de-0000-4000-8000-000000000099"],
        );
        assert_eq!(
            post(&app, &path, Some(&other_ca), grant).await.0,
            StatusCode::FORBIDDEN
        );
        let admin = oidc.token("admin-a", &[ADMIN_ROLE], &[CA]);
        for bad in [
            json!({"kind":"DELETE_CA"}),
            json!({"kind":"GRANT_OFFICER","officer_issuer":ISSUER}),
            json!({"kind":"GRANT_OFFICER","officer_issuer":ISSUER,"officer_subject":"x",
                   "person_id":"p"}),
            json!({"kind":"REGISTER_ISSUER","certificate_der":"AAAA"}),
            json!({"kind":"ENROLL_CREDENTIAL","officer_issuer":ISSUER,"officer_subject":"x",
                   "credential_id":"not base64!","person_id":"p","public_key":"AA"}),
        ] {
            assert_eq!(
                post(&app, &path, Some(&admin), bad).await.0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            post(
                &app,
                &format!("/v1/admin-changes/everything/{CA}/approval-challenges"),
                Some(&admin),
                Value::Null
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }

    fn test_database_url() -> Option<String> {
        match env::var("TRUST_REVOCATION_API_TEST_DATABASE_URL") {
            Ok(url) if !url.is_empty() => Some(url),
            _ => {
                assert_ne!(
                    env::var("TRUST_REQUIRE_DATABASE").as_deref(),
                    Ok("1"),
                    "TRUST_REVOCATION_API_TEST_DATABASE_URL is required when TRUST_REQUIRE_DATABASE=1"
                );
                eprintln!("SKIP: TRUST_REVOCATION_API_TEST_DATABASE_URL not configured");
                None
            }
        }
    }

    fn url_with_login(url: &str, user: &str) -> String {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (_, host) = rest.split_once('@').unwrap();
        format!("{scheme}://{user}:test-only-not-secret@{host}")
    }

    struct Authenticator {
        signer: EphemeralP256Signer,
        counter: u32,
    }

    impl Authenticator {
        fn new() -> Self {
            Self {
                signer: EphemeralP256Signer::generate("admin-authenticator").unwrap(),
                counter: 0,
            }
        }

        fn public_key(&self) -> Vec<u8> {
            let spki = self
                .signer
                .public_key_spki_der(self.signer.key_ref())
                .unwrap();
            SubjectPublicKeyInfoOwned::from_der(&spki)
                .unwrap()
                .subject_public_key
                .raw_bytes()
                .to_vec()
        }

        fn assertion(
            &mut self,
            credential_id: &[u8],
            challenge: &str,
            change: Option<&Value>,
        ) -> Value {
            self.counter += 1;
            let mut data = Sha256::digest(RP_ID.as_bytes()).to_vec();
            data.push(0x05);
            data.extend_from_slice(&self.counter.to_be_bytes());
            let client = format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}"}}"#
            )
            .into_bytes();
            let mut signed = data.clone();
            signed.extend_from_slice(&Sha256::digest(&client));
            let signature = self
                .signer
                .sign(
                    self.signer.key_ref(),
                    SignatureAlgorithm::EcdsaP256Sha256,
                    &signed,
                )
                .unwrap();
            let mut body = json!({
                "credential_id": URL_SAFE_NO_PAD.encode(credential_id),
                "authenticator_data": URL_SAFE_NO_PAD.encode(&data),
                "client_data_json": URL_SAFE_NO_PAD.encode(&client),
                "signature": URL_SAFE_NO_PAD.encode(&signature),
            });
            if let Some(change) = change {
                body["change"] = change.clone();
            }
            body
        }
    }

    /// A CA requiring signed administration, two admins with enrolled
    /// keys, and the API's CA-admin login.
    fn setup(url: &str) -> (String, Vec<u8>, Vec<u8>, Authenticator, Authenticator) {
        let mut owner = postgres::Client::connect(url, postgres::NoTls).unwrap();
        let ca: String = owner
            .query_one(
                "INSERT INTO ca(ca_id, display_name, policy_version)
                 VALUES (gen_random_uuid(), 'CA Admin API CA', 'v1') RETURNING ca_id::text",
                &[],
            )
            .unwrap()
            .get(0);
        owner
            .batch_execute(&format!(
                "INSERT INTO ca_revocation_policy(ca_id) VALUES ('{ca}');
                 INSERT INTO ca_admin_grant(issuer, subject, ca_id)
                     VALUES ('{ISSUER}', 'admin-a', '{ca}'), ('{ISSUER}', 'admin-b', '{ca}');
                 DO $$BEGIN
                   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_ca_admin_api_ci') THEN
                     CREATE ROLE trust_ca_admin_api_ci LOGIN PASSWORD 'test-only-not-secret';
                   END IF;
                 END$$;
                 GRANT trust_ca_admin TO trust_ca_admin_api_ci;"
            ))
            .unwrap();
        let (a, b) = (Authenticator::new(), Authenticator::new());
        let credential = |tag: u8| {
            let mut id = ca.replace('-', "").into_bytes();
            id.push(tag);
            id
        };
        let (a_id, b_id) = (credential(1), credential(2));
        let mut boot = PgRevocationStore::connect_lab(url).unwrap();
        for (id, subject, key) in [
            (&a_id, "admin-a", a.public_key()),
            (&b_id, "admin-b", b.public_key()),
        ] {
            let admin = OfficerIdentity {
                issuer: ISSUER,
                subject,
            };
            boot.enroll_admin_credential(&ca, id, &admin, &format!("person-{subject}"), &key)
                .unwrap();
        }
        owner
            .execute(
                "UPDATE ca_revocation_policy SET signed_admin_required = true
                 WHERE ca_id = $1::text::uuid",
                &[&ca],
            )
            .unwrap();
        (ca, a_id, b_id, a, b)
    }

    /// A grants an officer with B's signed approval over HTTP; the maker
    /// cannot approve, another admin cannot answer the maker's challenge,
    /// substituted content is refused; B rejects a second proposal.
    #[tokio::test]
    async fn signed_officer_grant_and_rejection_through_the_api() {
        let Some(url) = test_database_url() else {
            return;
        };
        let setup_url = url.clone();
        let (ca, a_id, b_id, mut a, mut b) = tokio::task::spawn_blocking(move || setup(&setup_url))
            .await
            .unwrap();
        let oidc = oidc();
        let (app, session) = app_with_session(
            oidc.verifier.clone(),
            &url_with_login(&url, "trust_ca_admin_api_ci"),
        );
        let a_token = oidc.token("admin-a", &[ADMIN_ROLE], &[&ca]);
        let b_token = oidc.token("admin-b", &[ADMIN_ROLE], &[&ca]);
        let grant =
            json!({"kind":"GRANT_OFFICER","officer_issuer":ISSUER,"officer_subject":"officer-1"});

        let (status, issued) = post(
            &app,
            &format!("/v1/cas/{ca}/admin-change-challenges"),
            Some(&a_token),
            grant.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        assert_eq!(issued["change_id"], Value::Null);
        let path = format!(
            "/v1/admin-change-challenges/{}/assertion",
            issued["challenge_id"].as_str().unwrap()
        );
        let webauthn = issued["webauthn_challenge"].as_str().unwrap().to_owned();
        // Another admin cannot answer it; a proposal must resend the content,
        // and only the signed content.
        let foreign = b.assertion(&b_id, &webauthn, Some(&grant));
        assert_eq!(
            post(&app, &path, Some(&b_token), foreign).await.0,
            StatusCode::FORBIDDEN
        );
        let missing = a.assertion(&a_id, &webauthn, None);
        assert_eq!(
            post(&app, &path, Some(&a_token), missing).await.0,
            StatusCode::BAD_REQUEST
        );
        let other =
            json!({"kind":"GRANT_OFFICER","officer_issuer":ISSUER,"officer_subject":"intruder"});
        let substituted = a.assertion(&a_id, &webauthn, Some(&other));
        assert_eq!(
            post(&app, &path, Some(&a_token), substituted).await.0,
            StatusCode::CONFLICT
        );
        let signed = a.assertion(&a_id, &webauthn, Some(&grant));
        let (status, proposed) = post(&app, &path, Some(&a_token), signed).await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        let change = proposed["change_id"].as_str().unwrap().to_owned();

        // The checker sees exactly what is pending, with the digest it signs.
        let pending_path = format!("/v1/cas/{ca}/pending-admin-changes");
        let (status, pending) = get(&app, &pending_path, &b_token).await;
        assert_eq!(status, StatusCode::OK, "{pending}");
        assert_eq!(pending.as_array().unwrap().len(), 1);
        assert_eq!(pending[0]["family"], "ca-admin");
        assert_eq!(pending[0]["change_id"], change.as_str());
        assert_eq!(pending[0]["kind"], "GRANT_OFFICER");
        assert_eq!(pending[0]["officer_subject"], "officer-1");
        assert_eq!(pending[0]["maker_subject"], "admin-a");
        assert_eq!(pending[0]["maker_signed"], true);
        assert_eq!(pending[0]["maker_evidence_verified"], true);
        let expected = trust_pki_core::revocation_store::officer_grant_digest(
            OfficerGrantAction::Grant,
            &OfficerIdentity {
                issuer: ISSUER,
                subject: "officer-1",
            },
        );
        assert_eq!(
            pending[0]["content_sha256"],
            URL_SAFE_NO_PAD.encode(expected)
        );
        let outsider = oidc.token(
            "admin-b",
            &[ADMIN_ROLE],
            &["5eedc0de-0000-4000-8000-000000000099"],
        );
        assert_eq!(
            get(&app, &pending_path, &outsider).await.0,
            StatusCode::FORBIDDEN
        );

        let approval = format!("/v1/admin-changes/ca-admin/{change}/approval-challenges");
        assert_eq!(
            post(&app, &approval, Some(&a_token), Value::Null).await.0,
            StatusCode::CONFLICT
        );
        let (status, issued) = post(&app, &approval, Some(&b_token), Value::Null).await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        assert_eq!(issued["change_id"], change.as_str());
        let path = format!(
            "/v1/admin-change-challenges/{}/assertion",
            issued["challenge_id"].as_str().unwrap()
        );
        let signed = b.assertion(&b_id, issued["webauthn_challenge"].as_str().unwrap(), None);
        let (status, approved) = post(&app, &path, Some(&b_token), signed).await;
        assert_eq!(status, StatusCode::OK, "{approved}");

        assert_eq!(get(&app, &pending_path, &b_token).await.1, json!([]));

        // A second proposal, rejected by B with a signature.
        let second =
            json!({"kind":"GRANT_OFFICER","officer_issuer":ISSUER,"officer_subject":"officer-2"});
        let (_, issued) = post(
            &app,
            &format!("/v1/cas/{ca}/admin-change-challenges"),
            Some(&a_token),
            second.clone(),
        )
        .await;
        let path = format!(
            "/v1/admin-change-challenges/{}/assertion",
            issued["challenge_id"].as_str().unwrap()
        );
        let signed = a.assertion(
            &a_id,
            issued["webauthn_challenge"].as_str().unwrap(),
            Some(&second),
        );
        let (_, proposed) = post(&app, &path, Some(&a_token), signed).await;
        let rejected = proposed["change_id"].as_str().unwrap().to_owned();
        let (status, issued) = post(
            &app,
            &format!("/v1/admin-changes/ca-admin/{rejected}/rejection-challenges"),
            Some(&b_token),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let path = format!(
            "/v1/admin-change-challenges/{}/assertion",
            issued["challenge_id"].as_str().unwrap()
        );
        let signed = b.assertion(&b_id, issued["webauthn_challenge"].as_str().unwrap(), None);
        assert_eq!(
            post(&app, &path, Some(&b_token), signed).await.0,
            StatusCode::OK
        );

        drop(app);
        tokio::task::spawn_blocking(move || {
            drop(session.lock().unwrap().take());
            let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
            let rows: Vec<(String, String)> = owner
                .query(
                    "SELECT officer_subject, status FROM ca_admin_change
                     WHERE ca_id = $1::text::uuid ORDER BY proposed_at",
                    &[&ca],
                )
                .unwrap()
                .iter()
                .map(|row| (row.get(0), row.get(1)))
                .collect();
            assert_eq!(
                rows,
                [
                    ("officer-1".to_owned(), "APPROVED".to_owned()),
                    ("officer-2".to_owned(), "REJECTED".to_owned())
                ]
            );
            let granted: i64 = owner
                .query_one(
                    "SELECT count(*) FROM revocation_officer_grant
                     WHERE ca_id = $1::text::uuid AND subject = 'officer-1'",
                    &[&ca],
                )
                .unwrap()
                .get(0);
            assert_eq!(granted, 1);
            let mut store = PgRevocationStore::connect_lab(&url).unwrap();
            let rp = RelyingParty {
                rp_id: RP_ID,
                origin: ORIGIN,
            };
            store
                .reverify_admin_change(AdminFamily::CaAdmin, &change, &rp)
                .unwrap();
            store
                .reverify_admin_change(AdminFamily::CaAdmin, &rejected, &rp)
                .unwrap();
        })
        .await
        .unwrap();
    }

    /// The raw parts of an `Authenticator::assertion` body.
    fn raw(body: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let field = |name: &str| {
            URL_SAFE_NO_PAD
                .decode(body[name].as_str().unwrap())
                .unwrap()
        };
        (
            field("authenticator_data"),
            field("client_data_json"),
            field("signature"),
        )
    }

    /// Signs the challenge `id` through the store (setup steps only).
    fn store_sign(
        store: &mut PgRevocationStore,
        authenticator: &mut Authenticator,
        credential_id: &[u8],
        id: &str,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let digest = store.admin_challenge(id).unwrap().claim.digest();
        raw(&authenticator.assertion(credential_id, &challenge_text(&digest), None))
    }

    /// A lost admin key A, a break-glass use enrolling C's key, and A's new
    /// key enrolled by B and C under dual control; the use is unreviewed.
    /// What `breakglass_setup` leaves: the CA, the unreviewed use, and the
    /// keys of the two admins (A, B) who will review it.
    struct BreakGlassFixture {
        ca: String,
        use_id: String,
        a_id: Vec<u8>,
        b_id: Vec<u8>,
        a: Authenticator,
        b: Authenticator,
    }

    fn breakglass_setup(url: &str) -> BreakGlassFixture {
        let (ca, a_id, b_id, _, mut b) = setup(url);
        let mut owner = postgres::Client::connect(url, postgres::NoTls).unwrap();
        owner
            .batch_execute(&format!(
                "INSERT INTO ca_admin_grant(issuer, subject, ca_id) VALUES ('{ISSUER}', 'admin-c', '{ca}')"
            ))
            .unwrap();
        owner
            .execute("SELECT remove_ca_admin_credential($1)", &[&a_id])
            .unwrap();
        let credential = |tag: u8| {
            let mut id = ca.replace('-', "").into_bytes();
            id.push(tag);
            id
        };
        let (bg_id, c_id, a2_id) = (credential(20), credential(3), credential(4));
        let (mut bg, mut c, a2) = (
            Authenticator::new(),
            Authenticator::new(),
            Authenticator::new(),
        );
        let mut store = PgRevocationStore::connect_lab(url).unwrap();
        store
            .enroll_breakglass_credential(
                &ca,
                &bg_id,
                "custodian",
                "person-custodian",
                &bg.public_key(),
            )
            .unwrap();
        let rp = RelyingParty {
            rp_id: RP_ID,
            origin: ORIGIN,
        };
        let admin_c = OfficerIdentity {
            issuer: ISSUER,
            subject: "admin-c",
        };
        let c_key = c.public_key();
        let c_content = CredentialContent {
            ca_id: &ca,
            credential_id: &c_id,
            officer: &admin_c,
            person_id: "person-admin-c",
            public_key_sec1: &c_key,
        };
        let id = store
            .issue_breakglass_challenge(&bg_id, &c_content, 120)
            .unwrap();
        let (data, client, signature) = store_sign(&mut store, &mut bg, &bg_id, &id);
        let assertion = Assertion {
            authenticator_data: &data,
            client_data_json: &client,
            signature_der: &signature,
        };
        let use_id = store
            .submit_breakglass(&id, &bg_id, &assertion, &rp, &c_content)
            .unwrap();
        let (admin_a, admin_b) = (
            OfficerIdentity {
                issuer: ISSUER,
                subject: "admin-a",
            },
            OfficerIdentity {
                issuer: ISSUER,
                subject: "admin-b",
            },
        );
        let a2_key = a2.public_key();
        let a2_content = CredentialContent {
            ca_id: &ca,
            credential_id: &a2_id,
            officer: &admin_a,
            person_id: "person-admin-a",
            public_key_sec1: &a2_key,
        };
        let enroll = AdminChange::AdminCredential(CredentialChangeKind::Enroll, &a2_content);
        let id = store
            .issue_admin_proposal_challenge(&ca, &enroll, &admin_b, 120)
            .unwrap();
        let (data, client, signature) = store_sign(&mut store, &mut b, &b_id, &id);
        let assertion = Assertion {
            authenticator_data: &data,
            client_data_json: &client,
            signature_der: &signature,
        };
        let change = store
            .submit_signed_admin(&id, &b_id, &assertion, &rp, Some(&enroll))
            .unwrap();
        let id = store
            .issue_admin_approval_challenge(AdminFamily::AdminCredential, &change, &admin_c, 120)
            .unwrap();
        let (data, client, signature) = store_sign(&mut store, &mut c, &c_id, &id);
        let assertion = Assertion {
            authenticator_data: &data,
            client_data_json: &client,
            signature_der: &signature,
        };
        store
            .submit_signed_admin(&id, &c_id, &assertion, &rp, None)
            .unwrap();
        BreakGlassFixture {
            ca,
            use_id,
            a_id: a2_id,
            b_id,
            a: a2,
            b,
        }
    }

    /// Migration 0045 over HTTP: admins list the CA's break-glass uses and
    /// review them with signed claims; the enrolled admin cannot review
    /// their own enrolment, another admin cannot answer a reviewer's
    /// challenge, and the use closes at the second review.
    #[tokio::test]
    async fn breakglass_uses_are_listed_and_reviewed_through_the_api() {
        let Some(url) = test_database_url() else {
            return;
        };
        let setup_url = url.clone();
        let BreakGlassFixture {
            ca,
            use_id,
            a_id,
            b_id,
            mut a,
            mut b,
        } = tokio::task::spawn_blocking(move || breakglass_setup(&setup_url))
            .await
            .unwrap();
        let oidc = oidc();
        let (app, session) = app_with_session(
            oidc.verifier.clone(),
            &url_with_login(&url, "trust_ca_admin_api_ci"),
        );
        let a_token = oidc.token("admin-a", &[ADMIN_ROLE], &[&ca]);
        let b_token = oidc.token("admin-b", &[ADMIN_ROLE], &[&ca]);
        let c_token = oidc.token("admin-c", &[ADMIN_ROLE], &[&ca]);

        let uses_path = format!("/v1/cas/{ca}/breakglass-uses");
        let (status, uses) = get(&app, &uses_path, &b_token).await;
        assert_eq!(status, StatusCode::OK, "{uses}");
        assert_eq!(uses.as_array().unwrap().len(), 1);
        assert_eq!(uses[0]["use_id"], use_id.as_str());
        assert_eq!(uses[0]["admin_subject"], "admin-c");
        assert_eq!(uses[0]["reviews"], 0);
        assert_eq!(uses[0]["reviewed"], false);
        let outsider = oidc.token(
            "admin-b",
            &[ADMIN_ROLE],
            &["5eedc0de-0000-4000-8000-000000000099"],
        );
        assert_eq!(
            get(&app, &uses_path, &outsider).await.0,
            StatusCode::FORBIDDEN
        );

        let review = format!("/v1/breakglass-uses/{use_id}/review-challenges");
        // Not by the admin it enrolled.
        assert_eq!(
            post(&app, &review, Some(&c_token), Value::Null).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(
                &app,
                "/v1/breakglass-uses/not-a-uuid/review-challenges",
                Some(&a_token),
                Value::Null
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post(&app, &review, Some(&outsider), Value::Null).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, issued) = post(&app, &review, Some(&a_token), Value::Null).await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        assert_eq!(issued["change_id"], use_id.as_str());
        let path = format!(
            "/v1/admin-change-challenges/{}/assertion",
            issued["challenge_id"].as_str().unwrap()
        );
        let webauthn = issued["webauthn_challenge"].as_str().unwrap().to_owned();
        let foreign = b.assertion(&b_id, &webauthn, None);
        assert_eq!(
            post(&app, &path, Some(&b_token), foreign).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, reviewed) = post(
            &app,
            &path,
            Some(&a_token),
            a.assertion(&a_id, &webauthn, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reviewed}");
        assert_eq!(reviewed, json!({"change_id": use_id, "reviewed": false}));

        let (status, issued) = post(&app, &review, Some(&b_token), Value::Null).await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let path = format!(
            "/v1/admin-change-challenges/{}/assertion",
            issued["challenge_id"].as_str().unwrap()
        );
        let signed = b.assertion(&b_id, issued["webauthn_challenge"].as_str().unwrap(), None);
        let (status, reviewed) = post(&app, &path, Some(&b_token), signed).await;
        assert_eq!(status, StatusCode::OK, "{reviewed}");
        assert_eq!(reviewed["reviewed"], true);
        let (_, uses) = get(&app, &uses_path, &b_token).await;
        assert_eq!(uses[0]["reviews"], 2);
        assert_eq!(uses[0]["reviewed"], true);
        assert_eq!(uses[0]["overdue"], false);

        drop(app);
        tokio::task::spawn_blocking(move || drop(session.lock().unwrap().take()))
            .await
            .unwrap();
    }

    /// The token's CA scope is checked before a decision or review
    /// challenge is written (as in the revocation API): an out-of-scope
    /// request writes nothing, an unknown change or use is 404.
    #[tokio::test]
    async fn out_of_scope_challenges_write_nothing() {
        let Some(url) = test_database_url() else {
            return;
        };
        let setup_url = url.clone();
        let fixture = tokio::task::spawn_blocking(move || breakglass_setup(&setup_url))
            .await
            .unwrap();
        let ca = fixture.ca.clone();
        let proposal_url = url.clone();
        let change = tokio::task::spawn_blocking(move || {
            let mut fixture = fixture;
            let mut store = PgRevocationStore::connect_lab(&proposal_url).unwrap();
            let grant = AdminChange::Officer(
                OfficerGrantAction::Grant,
                &OfficerIdentity {
                    issuer: ISSUER,
                    subject: "officer-x",
                },
            );
            let admin_b = OfficerIdentity {
                issuer: ISSUER,
                subject: "admin-b",
            };
            let id = store
                .issue_admin_proposal_challenge(&fixture.ca, &grant, &admin_b, 120)
                .unwrap();
            let (data, client, signature) =
                store_sign(&mut store, &mut fixture.b, &fixture.b_id, &id);
            let change = store
                .submit_signed_admin(
                    &id,
                    &fixture.b_id,
                    &Assertion {
                        authenticator_data: &data,
                        client_data_json: &client,
                        signature_der: &signature,
                    },
                    &RelyingParty {
                        rp_id: RP_ID,
                        origin: ORIGIN,
                    },
                    Some(&grant),
                )
                .unwrap();
            (change, fixture.use_id)
        })
        .await
        .unwrap();
        let (change, use_id) = change;
        let oidc = oidc();
        let (app, session) = app_with_session(
            oidc.verifier.clone(),
            &url_with_login(&url, "trust_ca_admin_api_ci"),
        );
        let outsider = oidc.token(
            "admin-a",
            &[ADMIN_ROLE],
            &["5eedc0de-0000-4000-8000-000000000099"],
        );
        for path in [
            format!("/v1/admin-changes/ca-admin/{change}/approval-challenges"),
            format!("/v1/admin-changes/ca-admin/{change}/rejection-challenges"),
            format!("/v1/breakglass-uses/{use_id}/review-challenges"),
        ] {
            assert_eq!(
                post(&app, &path, Some(&outsider), Value::Null).await.0,
                StatusCode::FORBIDDEN,
                "{path}"
            );
        }
        let admin = oidc.token("admin-a", &[ADMIN_ROLE], &[&ca]);
        let unknown = "5eedc0de-0000-4000-8000-0000000000aa";
        for path in [
            format!("/v1/admin-changes/ca-admin/{unknown}/approval-challenges"),
            format!("/v1/admin-changes/credential/{change}/approval-challenges"),
            format!("/v1/breakglass-uses/{unknown}/review-challenges"),
        ] {
            assert_eq!(
                post(&app, &path, Some(&admin), Value::Null).await.0,
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        drop(app);
        tokio::task::spawn_blocking(move || {
            drop(session.lock().unwrap().take());
            let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
            let written: i64 = owner
                .query_one(
                    "SELECT count(*) FROM ca_admin_challenge
                     WHERE ca_id = $1::text::uuid AND actor_subject = 'admin-a'
                       AND purpose IN ('APPROVE', 'REJECT', 'REVIEW')",
                    &[&ca],
                )
                .unwrap()
                .get(0);
            assert_eq!(written, 0);
        })
        .await
        .unwrap();
    }

    /// Reviewers see what the emergency key enrolled, re-verified by the
    /// Rust core (migration 0051); a use whose stored emergency signature
    /// does not verify cannot be reviewed (409) and stays open.
    #[tokio::test]
    async fn breakglass_review_requires_verified_evidence() {
        let Some(url) = test_database_url() else {
            return;
        };
        let setup_url = url.clone();
        let BreakGlassFixture { ca, use_id, .. } =
            tokio::task::spawn_blocking(move || breakglass_setup(&setup_url))
                .await
                .unwrap();
        let oidc = oidc();
        let (app, session) = app_with_session(
            oidc.verifier.clone(),
            &url_with_login(&url, "trust_ca_admin_api_ci"),
        );
        let a_token = oidc.token("admin-a", &[ADMIN_ROLE], &[&ca]);
        let detail_path = format!("/v1/breakglass-uses/{use_id}");
        let (status, detail) = get(&app, &detail_path, &a_token).await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["admin_subject"], "admin-c");
        assert_eq!(detail["person_id"], "person-admin-c");
        assert!(detail["public_key"].as_str().is_some());
        assert_eq!(detail["evidence_verified"], true);
        let outsider = oidc.token(
            "admin-a",
            &[ADMIN_ROLE],
            &["5eedc0de-0000-4000-8000-000000000099"],
        );
        assert_eq!(
            get(&app, &detail_path, &outsider).await.0,
            StatusCode::FORBIDDEN
        );

        // A superuser alters the stored emergency signature.
        let tamper_url = url.clone();
        let tampered = use_id.clone();
        tokio::task::spawn_blocking(move || {
            let mut owner = postgres::Client::connect(&tamper_url, postgres::NoTls).unwrap();
            owner
                .batch_execute(&format!(
                    "ALTER TABLE breakglass_use DISABLE TRIGGER breakglass_use_guard;
                     UPDATE breakglass_use
                        SET signature_der = set_byte(signature_der, octet_length(signature_der) - 1,
                                get_byte(signature_der, octet_length(signature_der) - 1) # 1)
                      WHERE use_id = '{tampered}';
                     ALTER TABLE breakglass_use ENABLE TRIGGER breakglass_use_guard"
                ))
                .unwrap();
        })
        .await
        .unwrap();
        let (status, detail) = get(&app, &detail_path, &a_token).await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["evidence_verified"], false);
        assert_eq!(
            post(
                &app,
                &format!("/v1/breakglass-uses/{use_id}/review-challenges"),
                Some(&a_token),
                Value::Null
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        drop(app);
        tokio::task::spawn_blocking(move || drop(session.lock().unwrap().take()))
            .await
            .unwrap();
    }

    /// One verified identity gets at most REQUESTS_PER_MINUTE requests per
    /// minute (429 beyond); other identities are unaffected. Counted before
    /// any database access, so the refusals below never reach it.
    #[tokio::test]
    async fn requests_are_rate_limited_per_identity() {
        let oidc = oidc();
        let app = app_with_session(oidc.verifier.clone(), "postgresql://unused.invalid/none").0;
        let path = format!("/v1/cas/{CA}/admin-change-challenges");
        let token = oidc.token("admin-a", &[ADMIN_ROLE], &[CA]);
        for _ in 0..60 {
            assert_eq!(
                post(&app, &path, Some(&token), json!({"kind":"DELETE_CA"}))
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            post(&app, &path, Some(&token), json!({"kind":"DELETE_CA"}))
                .await
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        let other = oidc.token("someone-else", &[ADMIN_ROLE], &[CA]);
        assert_eq!(
            post(&app, &path, Some(&other), json!({"kind":"DELETE_CA"}))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    /// Request bodies are bounded (64 KiB, 413) before they are parsed or
    /// authenticated; a legitimate request is far smaller.
    #[tokio::test]
    async fn oversized_bodies_are_refused() {
        let oidc = oidc();
        let app = app_with_session(oidc.verifier.clone(), "postgresql://unused.invalid/none").0;
        let path = format!("/v1/cas/{CA}/admin-change-challenges");
        let token = oidc.token("bulky", &[ADMIN_ROLE], &[CA]);
        let body = json!({"kind":"REGISTER_ISSUER", "certificate_der": "A".repeat(100_000)});
        assert!(body.to_string().len() > 64 * 1024);
        assert_eq!(
            post(&app, &path, Some(&token), body.clone()).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            post(&app, &path, None, body).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    /// A proposal past the CA's maximum age (0052) is shown as expired, and
    /// no approval challenge is issued for it (409) before anyone signs; it
    /// can still be rejected.
    #[tokio::test]
    async fn expired_proposals_are_flagged_and_not_offered_for_approval() {
        let Some(url) = test_database_url() else {
            return;
        };
        let setup_url = url.clone();
        let (ca, change) = tokio::task::spawn_blocking(move || {
            let (ca, a_id, _, mut a, _) = setup(&setup_url);
            let mut store = PgRevocationStore::connect_lab(&setup_url).unwrap();
            let officer = OfficerIdentity {
                issuer: ISSUER,
                subject: "officer-stale",
            };
            let grant = AdminChange::Officer(OfficerGrantAction::Grant, &officer);
            let admin_a = OfficerIdentity {
                issuer: ISSUER,
                subject: "admin-a",
            };
            let id = store
                .issue_admin_proposal_challenge(&ca, &grant, &admin_a, 120)
                .unwrap();
            let (data, client, signature) = store_sign(&mut store, &mut a, &a_id, &id);
            let change = store
                .submit_signed_admin(
                    &id,
                    &a_id,
                    &Assertion {
                        authenticator_data: &data,
                        client_data_json: &client,
                        signature_der: &signature,
                    },
                    &RelyingParty {
                        rp_id: RP_ID,
                        origin: ORIGIN,
                    },
                    Some(&grant),
                )
                .unwrap();
            let mut owner = postgres::Client::connect(&setup_url, postgres::NoTls).unwrap();
            owner
                .batch_execute(&format!(
                    "ALTER TABLE ca_admin_change DISABLE TRIGGER ca_admin_change_guard;
                     UPDATE ca_admin_change SET proposed_at = proposed_at - interval '8 days'
                     WHERE change_id = '{change}';
                     ALTER TABLE ca_admin_change ENABLE TRIGGER ca_admin_change_guard"
                ))
                .unwrap();
            (ca, change)
        })
        .await
        .unwrap();
        let oidc = oidc();
        let (app, session) = app_with_session(
            oidc.verifier.clone(),
            &url_with_login(&url, "trust_ca_admin_api_ci"),
        );
        let b_token = oidc.token("admin-b", &[ADMIN_ROLE], &[&ca]);
        let (status, pending) = get(
            &app,
            &format!("/v1/cas/{ca}/pending-admin-changes"),
            &b_token,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{pending}");
        assert_eq!(pending[0]["change_id"], change.as_str());
        assert_eq!(pending[0]["expired"], true);
        assert_eq!(
            post(
                &app,
                &format!("/v1/admin-changes/ca-admin/{change}/approval-challenges"),
                Some(&b_token),
                Value::Null
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (status, issued) = post(
            &app,
            &format!("/v1/admin-changes/ca-admin/{change}/rejection-challenges"),
            Some(&b_token),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        drop(app);
        tokio::task::spawn_blocking(move || drop(session.lock().unwrap().take()))
            .await
            .unwrap();
    }

    /// A checker sees whether the maker's stored signature of a CA-admin
    /// proposal re-verifies, and gets no approval challenge (409) for a
    /// proposal stored with a forged one; it can still be rejected.
    #[tokio::test]
    async fn forged_admin_maker_evidence_is_flagged_and_not_offered_for_approval() {
        let Some(url) = test_database_url() else {
            return;
        };
        let setup_url = url.clone();
        let (ca, change) = tokio::task::spawn_blocking(move || {
            let (ca, a_id, _, mut a, _) = setup(&setup_url);
            let mut store = PgRevocationStore::connect_lab(&setup_url).unwrap();
            let officer = OfficerIdentity {
                issuer: ISSUER,
                subject: "officer-forged",
            };
            let grant = AdminChange::Officer(OfficerGrantAction::Grant, &officer);
            let admin_a = OfficerIdentity {
                issuer: ISSUER,
                subject: "admin-a",
            };
            let id = store
                .issue_admin_proposal_challenge(&ca, &grant, &admin_a, 120)
                .unwrap();
            let (data, client, _) = store_sign(&mut store, &mut a, &a_id, &id);
            let (_, _, forged) = store_sign(&mut store, &mut Authenticator::new(), &a_id, &id);
            let mut direct = postgres::Client::connect(
                &format!("{setup_url}?options=-crole%3Dtrust_ca_admin"),
                postgres::NoTls,
            )
            .unwrap();
            let change: String = direct
                .query_one(
                    "SELECT propose_signed_admin_change($1::text::uuid, $2, $3, $4, $5,
                                                        NULL, NULL, $6, $7, NULL, NULL)::text",
                    &[
                        &id,
                        &a_id,
                        &data,
                        &client,
                        &forged,
                        &ISSUER,
                        &"officer-forged",
                    ],
                )
                .unwrap()
                .get(0);
            (ca, change)
        })
        .await
        .unwrap();
        let oidc = oidc();
        let (app, session) = app_with_session(
            oidc.verifier.clone(),
            &url_with_login(&url, "trust_ca_admin_api_ci"),
        );
        let b_token = oidc.token("admin-b", &[ADMIN_ROLE], &[&ca]);
        let (status, pending) = get(
            &app,
            &format!("/v1/cas/{ca}/pending-admin-changes"),
            &b_token,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{pending}");
        assert_eq!(pending[0]["change_id"], change.as_str());
        assert_eq!(pending[0]["maker_signed"], true);
        assert_eq!(pending[0]["maker_evidence_verified"], false);
        assert_eq!(
            post(
                &app,
                &format!("/v1/admin-changes/ca-admin/{change}/approval-challenges"),
                Some(&b_token),
                Value::Null
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(
                &app,
                &format!("/v1/admin-changes/ca-admin/{change}/rejection-challenges"),
                Some(&b_token),
                Value::Null
            )
            .await
            .0,
            StatusCode::CREATED
        );
        drop(app);
        tokio::task::spawn_blocking(move || drop(session.lock().unwrap().take()))
            .await
            .unwrap();
    }

    /// Every response forbids caching and content sniffing: challenges,
    /// evidence and CA data must not be kept by browsers or proxies.
    #[tokio::test]
    async fn responses_forbid_caching_and_sniffing() {
        let app = app_with_session(oidc().verifier.clone(), "postgresql://unused.invalid/none").0;
        let response = app
            .oneshot(
                Request::get("/v1/cas/5eedc0de-0000-4000-8000-000000000001/pending-admin-changes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    }
}
