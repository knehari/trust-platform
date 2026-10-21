//! Lab-only HTTP write API for certificate status changes (ADR-0005 control
//! plane, ADR-0007 signed approvals; both Proposed). LAB ONLY.
//!
//! Only the signed flow is offered; the Rust core decides:
//! * `POST /v1/cas/{ca_id}/status-change-challenges` (maker) and
//!   `POST /v1/status-changes/{change_id}/approval-challenges` (checker)
//!   return a single-use challenge: the WebAuthn challenge to sign is the
//!   SHA-256 of the canonical claim rebuilt from the database.
//! * `POST /v1/status-change-challenges/{challenge_id}/assertion` submits the
//!   authenticator's assertion; `PgRevocationStore::submit_signed` verifies
//!   it before anything is written, and the database re-checks the rest.
//!
//! The acting officer is the verified OIDC token's (issuer, subject), never
//! a request field (ADR-0003). The token must carry the
//! `trust-revocation-officer` role and the CA in `ca_ids`; the database
//! still requires the officer grant and an enrolled credential. Challenges
//! are bound to the officer who asked for them.
//!
//! The database login must hold only `trust_revocation_officer_api`
//! (`from_service_client` refuses privileged logins). The connection
//! follows the management API's policy: TLS 1.3 verified against
//! TRUST_DATABASE_CA_FILE by default; plaintext only with
//! TRUST_DATABASE_TLS=disable-lab (logged).
//! Environment: TRUST_OIDC_ISSUER, TRUST_OIDC_AUDIENCE,
//! TRUST_REVOCATION_DATABASE_URL, TRUST_DATABASE_TLS, TRUST_DATABASE_CA_FILE,
//! TRUST_WEBAUTHN_RP_ID,
//! TRUST_WEBAUTHN_ORIGIN, TRUST_REVOCATION_BIND (default 127.0.0.1:8083).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

// Shared with the read-only management API.
#[allow(dead_code)]
#[path = "../auth.rs"]
mod auth;
#[allow(dead_code)]
#[path = "../database.rs"]
mod database;

use auth::{Claims, OidcVerifier};
use axum::{
    extract::{Path, State},
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
    revocation::{OfficerIdentity, RevocationReason, StatusAction},
    revocation_store::{PgRevocationStore, RevocationStoreError, SignedChallenge},
    serial::SerialNumber,
    webauthn::{challenge_text, Assertion, RelyingParty},
};

const OFFICER_ROLE: &str = "trust-revocation-officer";
const CHALLENGE_TTL_SECONDS: i32 = 300;
const MAX_CONCURRENT_REQUESTS: usize = 8;
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalRequest {
    serial_hex: String,
    action: String,
    reason: Option<i16>,
    invalidity_unix: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionRequest {
    credential_id: String,
    authenticator_data: String,
    client_data_json: String,
    signature: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge_id: String,
    change_id: String,
    /// The `challenge` to pass to `navigator.credentials.get`.
    webauthn_challenge: String,
    expires_at_us: i64,
}

#[derive(Serialize)]
struct SubmittedResponse {
    change_id: String,
}

fn write_log(value: serde_json::Value) {
    // Never log tokens, assertions or database errors.
    let _ = writeln!(io::stderr().lock(), "{value}");
}

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/cas/{ca_id}/status-change-challenges",
            post(proposal_challenge),
        )
        .route(
            "/v1/status-changes/{change_id}/approval-challenges",
            post(approval_challenge),
        )
        .route(
            "/v1/status-change-challenges/{challenge_id}/assertion",
            post(submit_assertion),
        )
        .route(
            "/v1/cas/{ca_id}/pending-status-changes",
            get(pending_changes),
        )
        .route(
            "/v1/status-changes/{change_id}/rejection",
            post(reject_change),
        )
        .route(
            "/v1/status-changes/{change_id}/withdrawal",
            post(withdraw_change),
        )
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

async fn officer(headers: &HeaderMap, verifier: &OidcVerifier) -> Result<Claims, StatusCode> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = verifier
        .verify(token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !claims.roles.iter().any(|role| role == OFFICER_ROLE) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(claims)
}

fn in_scope(claims: &Claims, ca_id: &[u8; 16]) -> bool {
    let ca = hex_uuid(ca_id);
    claims.ca_ids.contains(&ca)
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
        RevocationStoreError::InvalidAssertion(_) | RevocationStoreError::InvalidCredential(_) => {
            StatusCode::BAD_REQUEST
        }
        RevocationStoreError::SignedApprovalRefused | RevocationStoreError::Denied(_) => {
            StatusCode::CONFLICT
        }
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Why a request on the officer session failed: the store (mapped by
/// `status_of`) or a refusal decided here.
enum Failure {
    Store(RevocationStoreError),
    Refused(StatusCode),
}

impl From<RevocationStoreError> for Failure {
    fn from(value: RevocationStoreError) -> Self {
        Self::Store(value)
    }
}

/// Runs `work` on the officer API session, reconnecting after a failure.
async fn with_store<T: Send + 'static>(
    state: &AppState,
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
        match work(session) {
            Ok(value) => Ok(value),
            Err(Failure::Refused(status)) => Err(status),
            Err(Failure::Store(error)) => {
                // A connection-level failure (no SQLSTATE): reconnect next time.
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

fn challenge_response(challenge_id: String, challenge: &SignedChallenge) -> Response {
    (
        StatusCode::CREATED,
        Json(ChallengeResponse {
            challenge_id,
            change_id: hex_uuid(&challenge.claim.change_id),
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
    Json(request): Json<ProposalRequest>,
) -> Result<Response, StatusCode> {
    let claims = officer(&headers, &state.verifier).await?;
    let ca_id = canonical_uuid(&ca_id).ok_or(StatusCode::NOT_FOUND)?;
    if !claims.ca_ids.contains(&ca_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let serial_bytes = (request.serial_hex.len() % 2 == 0)
        .then(|| {
            (0..request.serial_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(request.serial_hex.get(i..i + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()
        })
        .flatten()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let serial = SerialNumber::from_positive_der_content(&serial_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let action = match request.action.as_str() {
        "SUSPEND" => StatusAction::Suspend,
        "RELEASE" => StatusAction::Release,
        "REVOKE" => StatusAction::Revoke,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let reason = request
        .reason
        .map(RevocationReason::from_code)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let invalidity = request.invalidity_unix;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let (challenge_id, challenge) = with_store(&state, move |store| {
        let maker = OfficerIdentity {
            issuer: &issuer,
            subject: &subject,
        };
        let id = store.issue_proposal_challenge(
            &ca_id,
            &serial,
            action,
            reason,
            invalidity,
            &maker,
            CHALLENGE_TTL_SECONDS,
        )?;
        let challenge = store.signed_challenge(&id)?;
        Ok((id, challenge))
    })
    .await?;
    write_log(
        serde_json::json!({"event":"status_change_challenge_issued","step":"propose",
                                 "challenge_id":challenge_id}),
    );
    Ok(challenge_response(challenge_id, &challenge))
}

async fn approval_challenge(
    State(state): State<AppState>,
    Path(change_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let claims = officer(&headers, &state.verifier).await?;
    let change_id = canonical_uuid(&change_id).ok_or(StatusCode::NOT_FOUND)?;
    change_in_scope(&state, &claims, &change_id).await?;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let (challenge_id, challenge) = with_store(&state, move |store| {
        let checker = OfficerIdentity {
            issuer: &issuer,
            subject: &subject,
        };
        let id = store.issue_approval_challenge(&change_id, &checker, CHALLENGE_TTL_SECONDS)?;
        let challenge = store.signed_challenge(&id)?;
        Ok((id, challenge))
    })
    .await?;
    // Defence in depth: the challenge names the same CA.
    if !in_scope(&claims, &challenge.claim.ca_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    write_log(
        serde_json::json!({"event":"status_change_challenge_issued","step":"approve",
                                 "challenge_id":challenge_id}),
    );
    Ok(challenge_response(challenge_id, &challenge))
}

/// 404 for an unknown change, 403 outside the token's CA scope; checked
/// before anything is written.
async fn change_in_scope(
    state: &AppState,
    claims: &Claims,
    change_id: &str,
) -> Result<(), StatusCode> {
    let change = change_id.to_owned();
    let ca = with_store(state, move |store| Ok(store.status_change_ca(&change)?))
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;
    if claims.ca_ids.contains(&ca) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[derive(Serialize)]
struct PendingChange {
    change_id: String,
    serial_hex: String,
    action: String,
    reason: Option<i16>,
    invalidity_unix: Option<i64>,
    maker_issuer: String,
    maker_subject: String,
    proposed_at_unix: i64,
    maker_signed: bool,
}

async fn pending_changes(
    State(state): State<AppState>,
    Path(ca_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let claims = officer(&headers, &state.verifier).await?;
    let ca_id = canonical_uuid(&ca_id).ok_or(StatusCode::NOT_FOUND)?;
    if !claims.ca_ids.contains(&ca_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let pending = with_store(&state, move |store| {
        Ok(store.pending_status_changes(&ca_id)?)
    })
    .await?;
    let body: Vec<PendingChange> = pending
        .into_iter()
        .map(|change| PendingChange {
            change_id: change.change_id,
            serial_hex: change
                .serial_der_content
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            action: change.action,
            reason: change.reason_code,
            invalidity_unix: change.invalidity_at_unix,
            maker_issuer: change.maker_issuer,
            maker_subject: change.maker_subject,
            proposed_at_unix: change.proposed_at_unix,
            maker_signed: change.maker_signed,
        })
        .collect();
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// Rejection (a checker) and withdrawal (the maker) change no certificate
/// status; like the database functions they are not signed (ADR-0007 open
/// item), but the actor is still the token's.
async fn close_change(
    state: AppState,
    change_id: String,
    headers: HeaderMap,
    reject: bool,
) -> Result<Response, StatusCode> {
    let claims = officer(&headers, &state.verifier).await?;
    let change_id = canonical_uuid(&change_id).ok_or(StatusCode::NOT_FOUND)?;
    change_in_scope(&state, &claims, &change_id).await?;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let change = change_id.clone();
    with_store(&state, move |store| {
        let actor = OfficerIdentity {
            issuer: &issuer,
            subject: &subject,
        };
        if reject {
            store.reject(&change, &actor)?;
        } else {
            store.withdraw(&change, &actor)?;
        }
        Ok(())
    })
    .await?;
    write_log(serde_json::json!({
        "event": if reject { "status_change_rejected" } else { "status_change_withdrawn" },
        "change_id": change_id
    }));
    Ok((StatusCode::OK, Json(SubmittedResponse { change_id })).into_response())
}

async fn reject_change(
    State(state): State<AppState>,
    Path(change_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    close_change(state, change_id, headers, true).await
}

async fn withdraw_change(
    State(state): State<AppState>,
    Path(change_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    close_change(state, change_id, headers, false).await
}

async fn submit_assertion(
    State(state): State<AppState>,
    Path(challenge_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AssertionRequest>,
) -> Result<Response, StatusCode> {
    let claims = officer(&headers, &state.verifier).await?;
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
    let (rp_id, origin) = (state.rp_id.clone(), state.origin.clone());
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let ca_ids = claims.ca_ids.clone();
    let change_id = with_store(&state, move |store| {
        let challenge = store.signed_challenge(&challenge_id)?;
        // Only the officer the challenge was issued to may answer it, and
        // only within the token's CA scope.
        let ca = hex_uuid(&challenge.claim.ca_id);
        if (
            challenge.actor_issuer.as_str(),
            challenge.actor_subject.as_str(),
        ) != (issuer.as_str(), subject.as_str())
            || !ca_ids.contains(&ca)
        {
            return Err(Failure::Refused(StatusCode::FORBIDDEN));
        }
        Ok(store.submit_signed(
            &challenge_id,
            &credential_id,
            &Assertion {
                authenticator_data: &authenticator_data,
                client_data_json: &client_data_json,
                signature_der: &signature,
            },
            &RelyingParty {
                rp_id: &rp_id,
                origin: &origin,
            },
        )?)
    })
    .await;
    let change_id = match change_id {
        Ok(id) => id,
        Err(status) => {
            write_log(
                serde_json::json!({"event":"status_change_assertion_refused",
                                         "status":status.as_u16()}),
            );
            return Err(status);
        }
    };
    write_log(serde_json::json!({"event":"status_change_signed","change_id":change_id}));
    Ok((StatusCode::OK, Json(SubmittedResponse { change_id })).into_response())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = env::var("TRUST_OIDC_ISSUER")?;
    let audience = env::var("TRUST_OIDC_AUDIENCE")?;
    let database_url = env::var("TRUST_REVOCATION_DATABASE_URL")?;
    let rp_id = env::var("TRUST_WEBAUTHN_RP_ID")?;
    let origin = env::var("TRUST_WEBAUTHN_ORIGIN")?;
    let database_tls = database::tls_from_settings(
        env::var(database::TLS_MODE_ENV).ok().as_deref(),
        env::var(database::CA_FILE_ENV).ok().as_deref(),
    )?;
    if matches!(database_tls, database::DatabaseTls::DisabledForLab) {
        write_log(serde_json::json!({"event":"revocation_database_tls_disabled_lab"}));
    }
    let (check_url, check_tls) = (database_url.clone(), database_tls.clone());
    let checked = tokio::task::spawn_blocking(move || {
        database::connect_client(&check_url, &check_tls, STATEMENT_TIMEOUT_MS)
            .map(PgRevocationStore::from_service_client)
    })
    .await?;
    match checked {
        Err(()) => return Err("revocation database unavailable (connection or TLS failed)".into()),
        Ok(Err(RevocationStoreError::PrivilegedSession)) => {
            return Err("revocation database login is privileged; use an officer API login".into())
        }
        Ok(Err(_)) => return Err("revocation database check failed".into()),
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
    };
    let bind = env::var("TRUST_REVOCATION_BIND").unwrap_or_else(|_| "127.0.0.1:8083".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    write_log(serde_json::json!({"event":"revocation_api_started","bind":bind}));
    axum::serve(listener, router(state)).await?;
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
    use trust_pki_core::{
        lab_ca::EphemeralLabCa, officer_credential::CredentialChangeKind,
        revocation::CertificateStatus, revocation_store::CredentialContent,
    };
    use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};
    use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

    const ISSUER: &str = "https://issuer.example.test";
    const RP_ID: &str = "officer.lab.invalid";
    const ORIGIN: &str = "https://officer.lab.invalid";

    struct Oidc {
        verifier: OidcVerifier,
        signer: EncodingKey,
    }

    fn oidc() -> Oidc {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"revocation-test",
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
            header.kid = Some("revocation-test".into());
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

    /// The router and its database session, which a test must release on a
    /// blocking thread (the synchronous client cannot be dropped in async).
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
        });
        (router, session)
    }

    fn app(verifier: OidcVerifier, database_url: &str) -> Router {
        router(AppState {
            verifier,
            store: Arc::new(Mutex::new(None)),
            database_url: Arc::new(database_url.to_owned()),
            database_tls: database::DatabaseTls::DisabledForLab,
            rp_id: Arc::new(RP_ID.into()),
            origin: Arc::new(ORIGIN.into()),
            slots: Arc::new(Semaphore::new(4)),
        })
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

    const CA: &str = "5eedc0de-0000-4000-8000-000000000032";

    /// Refusals decided before any database access.
    #[tokio::test]
    async fn requests_are_authenticated_scoped_and_validated() {
        let oidc = oidc();
        // Never reached: every case below is refused before the database.
        let app = app(oidc.verifier.clone(), "postgresql://unused.invalid/none");
        let path = format!("/v1/cas/{CA}/status-change-challenges");
        let body = json!({"serial_hex":"01","action":"REVOKE","reason":1});
        assert_eq!(
            post(&app, &path, None, body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(&app, &path, Some("not-a-token"), body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let reader = oidc.token("maker", &["trust-ca-reader"], &[CA]);
        assert_eq!(
            post(&app, &path, Some(&reader), body.clone()).await.0,
            StatusCode::FORBIDDEN
        );
        let other_ca = oidc.token(
            "maker",
            &[OFFICER_ROLE],
            &["5eedc0de-0000-4000-8000-000000000099"],
        );
        assert_eq!(
            post(&app, &path, Some(&other_ca), body.clone()).await.0,
            StatusCode::FORBIDDEN
        );
        let token = oidc.token("maker", &[OFFICER_ROLE], &[CA]);
        for bad in [
            json!({"serial_hex":"0","action":"REVOKE","reason":1}),
            json!({"serial_hex":"zz","action":"REVOKE","reason":1}),
            json!({"serial_hex":"80","action":"REVOKE","reason":1}),
            json!({"serial_hex":"01","action":"DELETE","reason":1}),
            json!({"serial_hex":"01","action":"REVOKE","reason":7}),
        ] {
            assert_eq!(
                post(&app, &path, Some(&token), bad.clone()).await.0,
                StatusCode::BAD_REQUEST,
                "{bad}"
            );
        }
        // The actor is the token's, never a request field.
        let (status, _) = post(
            &app,
            &path,
            Some(&token),
            json!({"serial_hex":"01","action":"REVOKE","reason":1,"maker":"someone-else"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            post(
                &app,
                &format!("/v1/cas/{}/status-change-challenges", CA.to_uppercase()),
                Some(&token),
                body
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let assertion = json!({"credential_id":"!!","authenticator_data":"","client_data_json":"","signature":""});
        assert_eq!(
            post(
                &app,
                &format!("/v1/status-change-challenges/{CA}/assertion"),
                Some(&token),
                assertion
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
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

    fn url_as(url: &str, role: &str) -> String {
        let separator = if url.contains('?') { '&' } else { '?' };
        format!("{url}{separator}options=-crole%3D{role}")
    }

    fn url_with_login(url: &str, user: &str, password: &str) -> String {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (_, host) = rest.split_once('@').unwrap();
        format!("{scheme}://{user}:{password}@{host}")
    }

    struct Authenticator {
        signer: EphemeralP256Signer,
        counter: u32,
    }

    impl Authenticator {
        fn new() -> Self {
            Self {
                signer: EphemeralP256Signer::generate("api-authenticator").unwrap(),
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

        /// The JSON body a browser client would send for `challenge`.
        fn assertion(&mut self, credential_id: &[u8], challenge: &str) -> Value {
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
            json!({
                "credential_id": URL_SAFE_NO_PAD.encode(credential_id),
                "authenticator_data": URL_SAFE_NO_PAD.encode(&data),
                "client_data_json": URL_SAFE_NO_PAD.encode(&client),
                "signature": URL_SAFE_NO_PAD.encode(&signature),
            })
        }
    }

    /// A CA, one certificate, maker/checker grants, two CA admins, one
    /// enrolled credential each, and the API's officer login.
    fn setup(url: &str) -> (String, Vec<u8>, Vec<u8>, Authenticator, Authenticator) {
        let url = url.to_owned();
        let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        let ca: String = owner
            .query_one(
                "INSERT INTO ca(ca_id, display_name, policy_version)
                 VALUES (gen_random_uuid(), 'Revocation API CA', 'v1') RETURNING ca_id::text",
                &[],
            )
            .unwrap()
            .get(0);
        owner
            .batch_execute(&format!(
                "INSERT INTO ca_revocation_policy(ca_id) VALUES ('{ca}');
                 INSERT INTO revocation_officer_grant(issuer, subject, ca_id)
                     VALUES ('{ISSUER}', 'maker', '{ca}'), ('{ISSUER}', 'checker', '{ca}');
                 INSERT INTO ca_admin_grant(issuer, subject, ca_id)
                     VALUES ('{ISSUER}', 'admin-a', '{ca}'), ('{ISSUER}', 'admin-b', '{ca}');
                 INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                     requester_id, policy_version, state)
                     VALUES (gen_random_uuid(), '{ca}', 'api-1', sha256('csr'::bytea),
                             'requester', 'v1', 'PUBLISHED');
                 INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
                     SELECT '{ca}', '\\x01', request_id FROM certificate_request WHERE ca_id = '{ca}';
                 INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                     certificate_der, signed_at)
                     SELECT ca_id, serial_der_content, request_id, sha256('der'::bytea),
                            '\\x3003020101', now() FROM serial_reservation WHERE ca_id = '{ca}';
                 DO $$BEGIN
                   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_revocation_api_ci') THEN
                     CREATE ROLE trust_revocation_api_ci LOGIN PASSWORD 'test-only-not-secret';
                   END IF;
                 END$$;
                 GRANT trust_revocation_officer_api TO trust_revocation_api_ci;"
            ))
            .unwrap();
        let root = EphemeralLabCa::new("Sovereign Trust Lab Root")
            .unwrap()
            .root_certificate()
            .clone();
        PgRevocationStore::connect_lab(&url)
            .unwrap()
            .register_ca_issuer(&ca, &root, "bootstrap")
            .unwrap();
        let mut admin = PgRevocationStore::connect_lab(&url_as(&url, "trust_ca_admin")).unwrap();
        let (maker, checker) = (Authenticator::new(), Authenticator::new());
        let credential = |tag: u8| {
            let mut id = ca.replace('-', "").into_bytes();
            id.push(tag);
            id
        };
        let (maker_id, checker_id) = (credential(1), credential(2));
        for (id, subject, key) in [
            (&maker_id, "maker", maker.public_key()),
            (&checker_id, "checker", checker.public_key()),
        ] {
            let officer = OfficerIdentity {
                issuer: ISSUER,
                subject,
            };
            let content = CredentialContent {
                ca_id: &ca,
                credential_id: id,
                officer: &officer,
                person_id: subject,
                public_key_sec1: &key,
            };
            let admin_a = OfficerIdentity {
                issuer: ISSUER,
                subject: "admin-a",
            };
            let admin_b = OfficerIdentity {
                issuer: ISSUER,
                subject: "admin-b",
            };
            let change = admin
                .propose_credential_enrollment(&content, &admin_a)
                .unwrap();
            admin
                .approve_credential_change(
                    &change,
                    CredentialChangeKind::Enroll,
                    &content,
                    &admin_b,
                )
                .unwrap();
        }

        (ca, maker_id, checker_id, maker, checker)
    }

    /// Maker and checker revoke a certificate through HTTP with signed
    /// approvals; another officer cannot answer a challenge; a forged
    /// signature is refused before anything is written.
    #[tokio::test]
    async fn signed_revocation_through_the_api() {
        let Some(url) = test_database_url() else {
            return;
        };
        // The synchronous PostgreSQL client runs off the async runtime.
        let setup_url = url.clone();
        let (ca, maker_id, checker_id, mut maker, mut checker) =
            tokio::task::spawn_blocking(move || setup(&setup_url))
                .await
                .unwrap();
        let oidc = oidc();
        let api_url = url_with_login(&url, "trust_revocation_api_ci", "test-only-not-secret");
        let (app, session) = app_with_session(oidc.verifier.clone(), &api_url);
        let maker_token = oidc.token("maker", &[OFFICER_ROLE], &[&ca]);
        let checker_token = oidc.token("checker", &[OFFICER_ROLE], &[&ca]);

        let (status, issued) = post(
            &app,
            &format!("/v1/cas/{ca}/status-change-challenges"),
            Some(&maker_token),
            json!({"serial_hex":"01","action":"REVOKE","reason":1}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let challenge = issued["challenge_id"].as_str().unwrap().to_owned();
        let assertion_path = format!("/v1/status-change-challenges/{challenge}/assertion");
        // The checker cannot answer the maker's challenge, even with a valid
        // signature of their own.
        let wrong = checker.assertion(&checker_id, issued["webauthn_challenge"].as_str().unwrap());
        assert_eq!(
            post(&app, &assertion_path, Some(&checker_token), wrong)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        // A forged signature (another key) is refused before anything is written.
        let forged = Authenticator::new()
            .assertion(&maker_id, issued["webauthn_challenge"].as_str().unwrap());
        assert_eq!(
            post(&app, &assertion_path, Some(&maker_token), forged)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let signed = maker.assertion(&maker_id, issued["webauthn_challenge"].as_str().unwrap());
        let (status, submitted) = post(&app, &assertion_path, Some(&maker_token), signed).await;
        assert_eq!(status, StatusCode::OK, "{submitted}");
        let change = submitted["change_id"].as_str().unwrap().to_owned();
        assert_eq!(change, issued["change_id"].as_str().unwrap());

        // The maker cannot approve; the checker can.
        let approval_path = format!("/v1/status-changes/{change}/approval-challenges");
        assert_eq!(
            post(&app, &approval_path, Some(&maker_token), Value::Null)
                .await
                .0,
            StatusCode::CONFLICT
        );
        let (status, issued) = post(&app, &approval_path, Some(&checker_token), Value::Null).await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let challenge = issued["challenge_id"].as_str().unwrap();
        let signed = checker.assertion(&checker_id, issued["webauthn_challenge"].as_str().unwrap());
        let path = format!("/v1/status-change-challenges/{challenge}/assertion");
        let (status, _) = post(&app, &path, Some(&checker_token), signed.clone()).await;
        assert_eq!(status, StatusCode::OK);
        // Replay of the same assertion: the challenge is spent.
        assert_eq!(
            post(&app, &path, Some(&checker_token), signed).await.0,
            StatusCode::CONFLICT
        );

        drop(app);
        tokio::task::spawn_blocking(move || {
            drop(session.lock().unwrap().take());
            let mut reader = PgRevocationStore::connect_lab(&url).unwrap();
            assert_eq!(
                reader
                    .status(
                        &ca,
                        &SerialNumber::from_positive_der_content(&[0x01]).unwrap()
                    )
                    .unwrap(),
                CertificateStatus::Revoked
            );
            reader
                .reverify_signed_change(
                    &change,
                    &RelyingParty {
                        rp_id: RP_ID,
                        origin: ORIGIN,
                    },
                )
                .unwrap();
        })
        .await
        .unwrap();
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

    /// Pending list, withdrawal by the maker and rejection by a checker,
    /// with the actor taken from the token and the CA scope checked first.
    #[tokio::test]
    async fn pending_withdraw_and_reject_through_the_api() {
        let Some(url) = test_database_url() else {
            return;
        };
        let setup_url = url.clone();
        let (ca, maker_id, _, mut maker, _) =
            tokio::task::spawn_blocking(move || setup(&setup_url))
                .await
                .unwrap();
        let oidc = oidc();
        let api_url = url_with_login(&url, "trust_revocation_api_ci", "test-only-not-secret");
        let (app, session) = app_with_session(oidc.verifier.clone(), &api_url);
        let maker_token = oidc.token("maker", &[OFFICER_ROLE], &[&ca]);
        let checker_token = oidc.token("checker", &[OFFICER_ROLE], &[&ca]);
        let outsider = oidc.token(
            "checker",
            &[OFFICER_ROLE],
            &["5eedc0de-0000-4000-8000-000000000099"],
        );

        let issued_path = format!("/v1/cas/{ca}/status-change-challenges");
        let mut assertion = |challenge: &str| maker.assertion(&maker_id, challenge);
        let mut signed_proposal = async |app: &Router| {
            let (status, issued) = post(
                app,
                &issued_path,
                Some(&maker_token),
                json!({"serial_hex":"01","action":"REVOKE","reason":4}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{issued}");
            let path = format!(
                "/v1/status-change-challenges/{}/assertion",
                issued["challenge_id"].as_str().unwrap()
            );
            let body = assertion(issued["webauthn_challenge"].as_str().unwrap());
            let (status, submitted) = post(app, &path, Some(&maker_token), body).await;
            assert_eq!(status, StatusCode::OK, "{submitted}");
            submitted["change_id"].as_str().unwrap().to_owned()
        };

        let change = signed_proposal(&app).await;
        let pending_path = format!("/v1/cas/{ca}/pending-status-changes");
        let (status, pending) = get(&app, &pending_path, &checker_token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pending.as_array().unwrap().len(), 1);
        assert_eq!(pending[0]["change_id"], change.as_str());
        assert_eq!(pending[0]["serial_hex"], "01");
        assert_eq!(pending[0]["maker_signed"], true);
        assert_eq!(
            get(&app, &pending_path, &outsider).await.0,
            StatusCode::FORBIDDEN
        );

        let withdraw = format!("/v1/status-changes/{change}/withdrawal");
        // Out of scope, then not the maker: refused; the maker withdraws.
        assert_eq!(
            post(&app, &withdraw, Some(&outsider), Value::Null).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(&app, &withdraw, Some(&checker_token), Value::Null)
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(&app, &withdraw, Some(&maker_token), Value::Null)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(get(&app, &pending_path, &checker_token).await.1, json!([]));

        let change = signed_proposal(&app).await;
        let reject = format!("/v1/status-changes/{change}/rejection");
        // The maker cannot reject their own proposal; a checker can, once.
        assert_eq!(
            post(&app, &reject, Some(&maker_token), Value::Null).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(&app, &reject, Some(&checker_token), Value::Null)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            post(&app, &reject, Some(&checker_token), Value::Null)
                .await
                .0,
            StatusCode::CONFLICT
        );
        // An unknown change is 404 before anything else.
        assert_eq!(
            post(
                &app,
                "/v1/status-changes/5eedc0de-0000-4000-8000-0000000000aa/rejection",
                Some(&checker_token),
                Value::Null
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        drop(app);
        tokio::task::spawn_blocking(move || drop(session.lock().unwrap().take()))
            .await
            .unwrap();
    }
}
