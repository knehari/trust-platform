//! Laboratory write routes for certificate-profile drafts: record a new
//! immutable revision, and submit the latest revision for approval
//! (migration 0022, ADR-0010, Proposed). Nothing here approves, activates or
//! issues.
//!
//! Each route requires the `trust-profile-editor` token role and the CA in
//! the token's scope; the database then requires a server-owned
//! `profile-editor` grant for the same issuer, subject and CA. Writes go
//! through a separate login that can only execute the two lifecycle
//! functions. Every write carries an `Idempotency-Key` UUID: a replay of the
//! same request returns the recorded result, and any other use of the key is
//! refused with 409.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use postgres::error::SqlState;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    authenticate, profile_proposal, query_db, scoped_ca_id, valid_profile_id,
    valid_profile_revision, write_log, AppState, ProfileDraft,
};

pub(crate) const EDITOR_ROLE: &str = "trust-profile-editor";
/// Request bodies above this size are refused before parsing.
pub(crate) const MAX_WRITE_BODY_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDraftRequest {
    profile_id: String,
    display_name: String,
    policy_version: String,
    max_validity_days: i32,
    max_dns_sans: i32,
    proposed_dns_zones: Vec<String>,
    proposed_signature_suites: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    snapshot_sha256: String,
}

#[derive(Serialize)]
struct SubmissionResponse {
    ca_id: String,
    profile_id: String,
    revision: i32,
    status: &'static str,
    snapshot_sha256: String,
    submitted_at: String,
}

/// The verified principal and inputs common to the write routes.
pub(crate) struct WriteContext {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) ca_id: String,
    /// The Idempotency-Key, or empty when the route records nothing.
    pub(crate) operation: String,
    pub(crate) request_sha256: Vec<u8>,
    pub(crate) writer_url: crate::database::Database,
}

/// Verifies the token, the lifecycle role and the CA scope, then the
/// request's content type, size and (for recording routes) idempotency key.
pub(crate) async fn write_context(
    state: &AppState,
    headers: &HeaderMap,
    raw_ca: &str,
    body: &Bytes,
    required_role: &str,
    idempotent: bool,
) -> Result<WriteContext, StatusCode> {
    let claims = authenticate(headers, state).await?;
    if !claims.roles.iter().any(|role| role == required_role) {
        return Err(StatusCode::FORBIDDEN);
    }
    let ca_id = scoped_ca_id(raw_ca, &claims)?;
    let writer_url = state
        .writer_database_url
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if body.len() > MAX_WRITE_BODY_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let operation = if idempotent {
        headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .ok_or(StatusCode::BAD_REQUEST)?
            .to_string()
    } else {
        String::new()
    };
    Ok(WriteContext {
        issuer: claims.iss,
        subject: claims.sub,
        ca_id,
        operation,
        request_sha256: Sha256::digest(body).to_vec(),
        writer_url,
    })
}

/// Maps the lifecycle functions' SQLSTATEs (migrations 0022–0023) to HTTP.
pub(crate) fn write_status(error: &postgres::Error) -> StatusCode {
    let Some(code) = error.code() else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    if *code == SqlState::INSUFFICIENT_PRIVILEGE {
        StatusCode::FORBIDDEN
    } else if *code == SqlState::NO_DATA_FOUND {
        StatusCode::NOT_FOUND
    } else if code.code() == "TP409" || *code == SqlState::UNIQUE_VIOLATION {
        StatusCode::CONFLICT
    } else if code.code() == "TP422" {
        // Incompatible with the CA (migration 0024): policy version or suites.
        StatusCode::UNPROCESSABLE_ENTITY
    } else if code.code().starts_with("22") || code.code().starts_with("23") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

fn bounded(value: &str, max_chars: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max_chars
}

fn valid_create(request: &CreateDraftRequest) -> bool {
    valid_profile_id(&request.profile_id)
        && bounded(&request.display_name, 255)
        && bounded(&request.policy_version, 128)
        && (1..=825).contains(&request.max_validity_days)
        && (1..=100).contains(&request.max_dns_sans)
        && (1..=32).contains(&request.proposed_dns_zones.len())
        && request
            .proposed_dns_zones
            .iter()
            .all(|zone| bounded(zone, 253))
        && (1..=16).contains(&request.proposed_signature_suites.len())
        && request
            .proposed_signature_suites
            .iter()
            .all(|suite| bounded(suite, 64))
}

pub(crate) fn decode_sha256_hex(raw: &str) -> Option<Vec<u8>> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    (0..32)
        .map(|index| u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16).ok())
        .collect()
}

pub(crate) fn with_replay_header(mut response: Response, replayed: bool) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if replayed {
        response
            .headers_mut()
            .insert("idempotent-replayed", HeaderValue::from_static("true"));
    }
    response
}

/// `POST /v1/cas/{ca_id}/profile-drafts`: records the next revision of a
/// profile as an immutable DRAFT. 201 when recorded, 200 for a replay.
pub(crate) async fn create_profile_draft(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, EDITOR_ROLE, true).await?;
    let request: CreateDraftRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !valid_create(&request) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let WriteContext {
        issuer,
        subject,
        ca_id,
        operation,
        request_sha256,
        writer_url,
    } = context;
    let args = (
        issuer,
        subject.clone(),
        ca_id.clone(),
        request.profile_id.clone(),
        request.display_name.clone(),
        request.policy_version.clone(),
        request.max_validity_days,
        request.max_dns_sans,
        request.proposed_dns_zones.clone(),
        request.proposed_signature_suites.clone(),
        operation.clone(),
        request_sha256,
    );
    let outcome = query_db(writer_url, state.database_slots.clone(), move |db| {
        let result = db.query_one(
            "SELECT revision, created_at, replayed FROM create_profile_draft_lab(\
             $1, $2, $3::text::uuid, $4, $5, $6, $7, $8, $9, $10, $11::text::uuid, $12)",
            &[
                &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7, &args.8,
                &args.9, &args.10, &args.11,
            ],
        );
        Ok(match result {
            Ok(row) => Ok((
                row.get::<_, i32>(0),
                row.get::<_, String>(1),
                row.get::<_, bool>(2),
            )),
            Err(error) => Err(write_status(&error)),
        })
    })
    .await??;
    let (revision, created_at, replayed) = outcome;
    let proposal_warnings = profile_proposal::syntax_warnings(
        &request.display_name,
        &request.policy_version,
        &request.proposed_dns_zones,
        &request.proposed_signature_suites,
    );
    let mut draft = ProfileDraft {
        ca_id: ca_id.clone(),
        profile_id: request.profile_id,
        revision,
        display_name: request.display_name,
        policy_version: request.policy_version,
        max_validity_days: request.max_validity_days,
        max_dns_sans: request.max_dns_sans,
        proposed_dns_zones: request.proposed_dns_zones,
        proposed_signature_suites: request.proposed_signature_suites,
        created_by: subject,
        created_at,
        status: "DRAFT",
        submitted_at: None,
        approval_count: 0,
        decided_at: None,
        activated_at: None,
        ended_at: None,
        proposal_warnings,
        snapshot_sha256: String::new(),
    };
    draft.snapshot_sha256 = profile_proposal::snapshot_sha256(&draft);
    write_log(serde_json::json!({
        "event": "profile_draft_created", "ca_id": ca_id, "profile_id": draft.profile_id,
        "revision": revision, "operation_id": operation, "replayed": replayed,
    }));
    let status = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(with_replay_header(
        (status, Json(draft)).into_response(),
        replayed,
    ))
}

/// `POST /v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}/submission`:
/// submits the latest revision when the caller names its exact digest and
/// it has no syntax warning. 201 when recorded, 200 for a replay.
pub(crate) async fn submit_profile_draft(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, profile_id, raw_revision)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, EDITOR_ROLE, true).await?;
    if !valid_profile_id(&profile_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let revision = valid_profile_revision(&raw_revision)?;
    let request: SubmitRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let digest = decode_sha256_hex(&request.snapshot_sha256).ok_or(StatusCode::BAD_REQUEST)?;
    let WriteContext {
        issuer,
        subject,
        ca_id,
        operation,
        request_sha256,
        writer_url,
    } = context;
    let args = (
        issuer,
        subject,
        ca_id.clone(),
        profile_id.clone(),
        revision,
        digest,
        operation.clone(),
        request_sha256,
    );
    let outcome = query_db(writer_url, state.database_slots.clone(), move |db| {
        let mut tx = db.transaction()?;
        let row = match tx.query_one(
            "SELECT submitted_at, replayed, display_name, policy_version, \
             proposed_dns_zones, proposed_signature_suites \
             FROM submit_profile_draft_lab($1, $2, $3::text::uuid, $4, $5, $6, $7::text::uuid, $8)",
            &[
                &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
            ],
        ) {
            Ok(row) => row,
            Err(error) => return Ok(Err(write_status(&error))),
        };
        let replayed: bool = row.get(1);
        let warnings = profile_proposal::syntax_warnings(
            &row.get::<_, String>(2),
            &row.get::<_, String>(3),
            &row.get::<_, Vec<String>>(4),
            &row.get::<_, Vec<String>>(5),
        );
        // A revision with syntax warnings cannot be submitted: the whole
        // submission, its lifecycle event and its audit event roll back.
        if !warnings.is_empty() && !replayed {
            tx.rollback()?;
            return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
        }
        tx.commit()?;
        Ok(Ok((row.get::<_, String>(0), replayed)))
    })
    .await??;
    let (submitted_at, replayed) = outcome;
    write_log(serde_json::json!({
        "event": "profile_draft_submitted", "ca_id": ca_id, "profile_id": profile_id,
        "revision": revision, "operation_id": operation, "replayed": replayed,
    }));
    let status = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(with_replay_header(
        (
            status,
            Json(SubmissionResponse {
                ca_id,
                profile_id,
                revision,
                status: "SUBMITTED",
                snapshot_sha256: request.snapshot_sha256,
                submitted_at,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// Startup check for the writer login: a member of `trust_profile_writer`
/// only, without any table or view privilege, on a database with migration
/// 0022.
pub(crate) fn restricted_writer_role(db: &mut postgres::Client) -> Result<bool, postgres::Error> {
    db.query_one(
        "SELECT pg_has_role(current_user,'trust_profile_writer','member') \
         AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname='trust_api_reader' \
             AND pg_has_role(current_user,r.oid,'member')) \
         AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=current_user \
             AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)) \
         AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
             WHERE n.nspname='public' AND c.relkind IN ('r','p','m','f','v') \
             AND has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) \
         AND management_profile_lifecycle_version() = 1 \
         AND management_profile_decision_version() = 1 \
         AND management_profile_activation_version() = 1",
        &[],
    )
    .map(|row| row.get::<_, bool>(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_hex_is_exact_lowercase_sha256() {
        let hex = "5e74e6260bf6f56f899c323e3525cfac09a2fd1c9b01653e2c47247d08f72330";
        assert_eq!(decode_sha256_hex(hex).unwrap().len(), 32);
        assert!(decode_sha256_hex(&hex.to_uppercase()).is_none());
        assert!(decode_sha256_hex(&hex[1..]).is_none());
        assert!(decode_sha256_hex(&format!("{}g", &hex[1..])).is_none());
    }

    #[test]
    fn create_request_bounds_match_the_table_checks() {
        let valid = CreateDraftRequest {
            profile_id: "server-lab".into(),
            display_name: "Server".into(),
            policy_version: "v1".into(),
            max_validity_days: 90,
            max_dns_sans: 5,
            proposed_dns_zones: vec!["lab.invalid".into()],
            proposed_signature_suites: vec!["P256-SHA256".into()],
        };
        assert!(valid_create(&valid));
        for change in [
            |r: &mut CreateDraftRequest| r.profile_id = "Server".into(),
            |r: &mut CreateDraftRequest| r.display_name = String::new(),
            |r: &mut CreateDraftRequest| r.display_name = "x".repeat(256),
            |r: &mut CreateDraftRequest| r.max_validity_days = 826,
            |r: &mut CreateDraftRequest| r.max_dns_sans = 0,
            |r: &mut CreateDraftRequest| r.proposed_dns_zones.clear(),
            |r: &mut CreateDraftRequest| r.proposed_signature_suites = vec!["x".into(); 17],
        ] {
            let mut request = CreateDraftRequest {
                profile_id: valid.profile_id.clone(),
                display_name: valid.display_name.clone(),
                policy_version: valid.policy_version.clone(),
                max_validity_days: valid.max_validity_days,
                max_dns_sans: valid.max_dns_sans,
                proposed_dns_zones: valid.proposed_dns_zones.clone(),
                proposed_signature_suites: valid.proposed_signature_suites.clone(),
            };
            change(&mut request);
            assert!(!valid_create(&request));
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(serde_json::from_str::<SubmitRequest>(
            r#"{"snapshot_sha256":"00","status":"APPROVED"}"#
        )
        .is_err());
    }
}
