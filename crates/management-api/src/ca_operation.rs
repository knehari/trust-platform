//! Laboratory routes to suspend, reactivate and retire an activated CA
//! (migration 0027, ADR-0015, Proposed).
//!
//! Stopping is easy, resuming or ending is controlled:
//! * a CA administrator suspends an ACTIVE CA at once;
//! * reactivation or retirement is a change request by an administrator,
//!   approved by two CA approvers who sign the exact claim the database
//!   builds (verified here before commit, as in ADR-0014), then applied by
//!   an administrator who did not decide. Retirement also retires the CA's
//!   active profile revisions, and is final.
//!
//! While a CA is not ACTIVE, the database refuses to activate profile
//! revisions for it. No issuance path uses any CA yet.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::{
    ca_decision::CA_APPROVER_ROLE,
    ca_proposal::{printable, ADMINISTRATOR_ROLE},
    profile_decision::signature_verifies,
    profile_lifecycle::{platform_write_context, with_replay_header, write_status, WriteContext},
    query_db, write_log, AppState,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuspensionRequest {
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeRequest {
    action: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    decision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRequest {
    decision: String,
    issued_at: String,
    signature_der_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationRequest {}

#[derive(Serialize)]
struct StateResponse {
    ca_id: String,
    operational_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retired_revisions: Option<i32>,
}

#[derive(Serialize)]
struct ChangeRequestResponse {
    ca_id: String,
    request_id: String,
    action: String,
    from_state: String,
}

#[derive(Serialize)]
struct ClaimResponse {
    decision: String,
    claim: String,
    key_id: String,
    issued_at: String,
    valid_for_seconds: u32,
}

#[derive(Serialize)]
struct DecisionResponse {
    ca_id: String,
    request_id: String,
    decision: String,
    request_status: String,
    approval_count: i32,
}

fn canonical_uuid(raw: &str) -> Result<String, StatusCode> {
    Ok(uuid::Uuid::parse_str(raw)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string())
}

fn valid_decision(raw: &str) -> bool {
    matches!(raw, "approve" | "reject")
}

fn valid_change_action(raw: &str) -> bool {
    matches!(raw, "reactivate" | "retire")
}

fn created_or_replayed(replayed: bool) -> StatusCode {
    if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    }
}

/// `POST /v1/ca-proposals/{ca_id}/suspension`: suspends an ACTIVE CA at
/// once. 201 when suspended, 200 for a replay.
pub(crate) async fn suspend_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, ADMINISTRATOR_ROLE, true).await?;
    let ca_id = canonical_uuid(&raw_ca)?;
    let request: SuspensionRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !printable(&request.reason, 500) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let WriteContext {
        issuer,
        subject,
        operation,
        request_sha256,
        writer_url,
        ..
    } = context;
    let args = (
        issuer,
        subject,
        ca_id.clone(),
        request.reason,
        operation.clone(),
        request_sha256,
    );
    let (operational_state, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT operational_state, replayed FROM suspend_ca_lab($1, $2, \
                     $3::text::uuid, $4, $5::text::uuid, $6)",
                    &[&args.0, &args.1, &args.2, &args.3, &args.4, &args.5],
                ) {
                    Ok(row) => Ok((row.get::<_, String>(0), row.get::<_, bool>(1))),
                    Err(error) => Err(write_status(&error)),
                },
            )
        })
        .await??;
    write_log(serde_json::json!({
        "event": "ca_suspended", "ca_id": ca_id, "operation_id": operation, "replayed": replayed,
    }));
    Ok(with_replay_header(
        (
            created_or_replayed(replayed),
            Json(StateResponse {
                ca_id,
                operational_state,
                retired_revisions: None,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `POST /v1/ca-proposals/{ca_id}/change-requests`: requests reactivation
/// of a SUSPENDED CA or retirement of an ACTIVE or SUSPENDED one.
pub(crate) async fn request_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, ADMINISTRATOR_ROLE, true).await?;
    let ca_id = canonical_uuid(&raw_ca)?;
    let request: ChangeRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !valid_change_action(&request.action) || !printable(&request.reason, 500) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let WriteContext {
        issuer,
        subject,
        operation,
        request_sha256,
        writer_url,
        ..
    } = context;
    let action = request.action.clone();
    let args = (
        issuer,
        subject,
        ca_id.clone(),
        request.action,
        request.reason,
        operation.clone(),
        request_sha256,
    );
    let (request_id, from_state, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT request_id::text, from_state, replayed FROM request_ca_change_lab($1, \
                     $2, $3::text::uuid, $4, $5, $6::text::uuid, $7)",
                    &[
                        &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6,
                    ],
                ) {
                    Ok(row) => Ok((
                        row.get::<_, String>(0),
                        row.get::<_, String>(1),
                        row.get::<_, bool>(2),
                    )),
                    Err(error) => Err(write_status(&error)),
                },
            )
        })
        .await??;
    write_log(serde_json::json!({
        "event": "ca_change_requested", "ca_id": ca_id, "request_id": request_id,
        "action": action, "operation_id": operation, "replayed": replayed,
    }));
    Ok(with_replay_header(
        (
            created_or_replayed(replayed),
            Json(ChangeRequestResponse {
                ca_id,
                request_id,
                action,
                from_state,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `POST …/change-requests/{request_id}/decision-claims`: the claim to sign.
/// Records nothing; it expires ten minutes after `issued_at`.
pub(crate) async fn prepare_change_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_request)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, CA_APPROVER_ROLE, false).await?;
    let ca_id = canonical_uuid(&raw_ca)?;
    let request_id = canonical_uuid(&raw_request)?;
    let request: ClaimRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !valid_decision(&request.decision) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let WriteContext {
        issuer,
        subject,
        writer_url,
        ..
    } = context;
    let decision = request.decision.clone();
    let (claim, key_id, issued_at) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT claim, key_id, issued_at FROM prepare_ca_change_decision_lab($1, $2, \
                     $3::text::uuid, $4::text::uuid, $5)",
                    &[&issuer, &subject, &ca_id, &request_id, &decision],
                ) {
                    Ok(row) => Ok((
                        row.get::<_, String>(0),
                        row.get::<_, String>(1),
                        row.get::<_, String>(2),
                    )),
                    Err(error) => Err(write_status(&error)),
                },
            )
        })
        .await??;
    Ok(with_replay_header(
        Json(ClaimResponse {
            decision: request.decision,
            claim,
            key_id,
            issued_at,
            valid_for_seconds: 600,
        })
        .into_response(),
        false,
    ))
}

/// `POST …/change-requests/{request_id}/decisions`: records a signed
/// decision; 422 when the signature does not verify (nothing is kept).
pub(crate) async fn record_change_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_request)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, CA_APPROVER_ROLE, true).await?;
    let ca_id = canonical_uuid(&raw_ca)?;
    let request_id = canonical_uuid(&raw_request)?;
    let request: DecisionRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let issued_at = crate::valid_utc_timestamp(&request.issued_at)?;
    let signature = STANDARD
        .decode(request.signature_der_base64.trim())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if !valid_decision(&request.decision) || !(8..=80).contains(&signature.len()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let WriteContext {
        issuer,
        subject,
        operation,
        request_sha256,
        writer_url,
        ..
    } = context;
    let args = (
        issuer,
        subject,
        ca_id.clone(),
        request_id.clone(),
        request.decision.clone(),
        issued_at,
        signature,
        operation.clone(),
        request_sha256,
    );
    let (request_status, approval_count, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            let mut tx = db.transaction()?;
            let row = match tx.query_one(
                "SELECT claim, public_key_sec1, signature_der, request_status, approval_count, \
                 replayed FROM record_ca_change_decision_lab($1, $2, $3::text::uuid, \
                 $4::text::uuid, $5, $6::text::timestamptz, $7, $8::text::uuid, $9)",
                &[
                    &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7, &args.8,
                ],
            ) {
                Ok(row) => row,
                Err(error) => return Ok(Err(write_status(&error))),
            };
            let claim: String = row.get(0);
            let public_key: Vec<u8> = row.get(1);
            let signature: Vec<u8> = row.get(2);
            if !signature_verifies(&public_key, &claim, &signature) {
                tx.rollback()?;
                return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
            }
            let status: String = row.get(3);
            let approvals: i32 = row.get(4);
            let replayed: bool = row.get(5);
            tx.commit()?;
            Ok(Ok((status, approvals, replayed)))
        })
        .await??;
    write_log(serde_json::json!({
        "event": "ca_change_decision_recorded", "ca_id": ca_id, "request_id": request_id,
        "decision": request.decision, "status": request_status, "operation_id": operation,
        "replayed": replayed,
    }));
    Ok(with_replay_header(
        (
            created_or_replayed(replayed),
            Json(DecisionResponse {
                ca_id,
                request_id,
                decision: request.decision,
                request_status,
                approval_count,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `POST …/change-requests/{request_id}/application`: applies an APPROVED
/// request. 201 when applied, 200 for a replay.
pub(crate) async fn apply_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_request)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, ADMINISTRATOR_ROLE, true).await?;
    let ca_id = canonical_uuid(&raw_ca)?;
    let request_id = canonical_uuid(&raw_request)?;
    let _: ApplicationRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let WriteContext {
        issuer,
        subject,
        operation,
        request_sha256,
        writer_url,
        ..
    } = context;
    let args = (
        issuer,
        subject,
        ca_id.clone(),
        request_id.clone(),
        operation.clone(),
        request_sha256,
    );
    let (operational_state, retired, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT operational_state, retired_revisions, replayed FROM \
                     apply_ca_change_lab($1, $2, $3::text::uuid, $4::text::uuid, \
                     $5::text::uuid, $6)",
                    &[&args.0, &args.1, &args.2, &args.3, &args.4, &args.5],
                ) {
                    Ok(row) => Ok((
                        row.get::<_, String>(0),
                        row.get::<_, i32>(1),
                        row.get::<_, bool>(2),
                    )),
                    Err(error) => Err(write_status(&error)),
                },
            )
        })
        .await??;
    write_log(serde_json::json!({
        "event": "ca_change_applied", "ca_id": ca_id, "request_id": request_id,
        "state": operational_state, "retired_revisions": retired,
        "operation_id": operation, "replayed": replayed,
    }));
    Ok(with_replay_header(
        (
            created_or_replayed(replayed),
            Json(StateResponse {
                ca_id,
                operational_state,
                retired_revisions: Some(retired),
            }),
        )
            .into_response(),
        replayed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_take_known_actions_and_fields_only() {
        assert!(valid_change_action("reactivate") && valid_change_action("retire"));
        assert!(!valid_change_action("suspend") && !valid_change_action("activate"));
        assert!(serde_json::from_str::<ApplicationRequest>("{}").is_ok());
        assert!(serde_json::from_str::<ApplicationRequest>(r#"{"state":"ACTIVE"}"#).is_err());
        assert!(
            serde_json::from_str::<SuspensionRequest>(r#"{"reason":"x","until":"y"}"#).is_err()
        );
        assert!(serde_json::from_str::<ChangeRequest>(
            r#"{"action":"retire","reason":"x","force":true}"#
        )
        .is_err());
    }
}
