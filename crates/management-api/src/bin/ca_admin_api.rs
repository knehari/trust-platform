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

use auth::{Claims, OidcVerifier};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
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

#[derive(Serialize)]
struct SubmittedResponse {
    change_id: String,
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

fn family(text: &str) -> Option<AdminFamily> {
    match text {
        "ca-admin" => Some(AdminFamily::CaAdmin),
        "credential" => Some(AdminFamily::Credential),
        "admin-credential" => Some(AdminFamily::AdminCredential),
        _ => None,
    }
}

async fn admin(headers: &HeaderMap, verifier: &OidcVerifier) -> Result<Claims, StatusCode> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = verifier
        .verify(token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !claims.roles.iter().any(|role| role == ADMIN_ROLE) {
        return Err(StatusCode::FORBIDDEN);
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
    let claims = admin(&headers, &state.verifier).await?;
    let ca_id = canonical_uuid(&ca_id).ok_or(StatusCode::NOT_FOUND)?;
    if !claims.ca_ids.contains(&ca_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let change = OwnedChange::parse(&ca_id, &request)?;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let (challenge_id, challenge) = with_store(&state, move |store| {
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

/// Approval or rejection by another admin. The database checks the actor's
/// admin grant on the change's CA before issuing; the token's CA scope is
/// checked on the issued challenge (nothing is changed by issuing one).
async fn decision_challenge(
    state: AppState,
    family_text: String,
    change_id: String,
    headers: HeaderMap,
    step: SignedStep,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state.verifier).await?;
    let family = family(&family_text).ok_or(StatusCode::NOT_FOUND)?;
    let change_id = canonical_uuid(&change_id).ok_or(StatusCode::NOT_FOUND)?;
    let (issuer, subject) = (claims.iss.clone(), claims.sub.clone());
    let (challenge_id, challenge) = with_store(&state, move |store| {
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

async fn submit_assertion(
    State(state): State<AppState>,
    Path(challenge_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AssertionRequest>,
) -> Result<Response, StatusCode> {
    let claims = admin(&headers, &state.verifier).await?;
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
    let result = with_store(&state, move |store| {
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
        Ok((id, challenge.purpose))
    })
    .await;
    let (change_id, step) = match result {
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
        _ => "admin_change_approved",
    };
    write_log(serde_json::json!({"event":event,"change_id":change_id}));
    Ok((StatusCode::OK, Json(SubmittedResponse { change_id })).into_response())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    };
    let bind = env::var("TRUST_CA_ADMIN_BIND").unwrap_or_else(|_| "127.0.0.1:8084".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    write_log(serde_json::json!({"event":"ca_admin_api_started","bind":bind}));
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
        });
        (router, session)
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
}
