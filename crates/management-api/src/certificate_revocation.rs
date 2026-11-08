//! Laboratory revocation of certificates issued for applications (migration
//! 0030, ADR-0018, Proposed).
//!
//! - `POST /v1/cas/{ca_id}/certificate-applications/{id}/revocation-requests`:
//!   the application's own requester (`trust-certificate-requester`, still
//!   granted) or a registration officer asks for revocation, with an RFC
//!   5280 reason code from the laboratory's closed list and a reason.
//! - `POST …/revocation-requests/{revocation_id}/decision`: a registration
//!   officer who did not ask approves or rejects it, once. Approval writes
//!   the core revocation row; the certificate appears on the next CRL.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    ca_proposal::printable,
    certificate_application::{OFFICER_ROLE, REQUESTER_ROLE},
    profile_lifecycle::{with_replay_header, write_context, write_status, WriteContext},
    query_db, write_log, AppState,
};

/// unspecified, keyCompromise, affiliationChanged, superseded,
/// cessationOfOperation, privilegeWithdrawn; the database applies the same
/// closed list.
pub(crate) const REASON_CODES: [i16; 6] = [0, 1, 3, 4, 5, 9];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationRequest {
    reason_code: i16,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationDecision {
    decision: String,
    reason: String,
}

#[derive(Serialize)]
struct RequestResponse {
    ca_id: String,
    application_id: String,
    revocation_id: String,
    status: &'static str,
}

#[derive(Serialize)]
struct DecisionResponse {
    ca_id: String,
    application_id: String,
    revocation_id: String,
    status: String,
    revoked_at: Option<String>,
}

fn uuid_text(raw: &str) -> Result<String, StatusCode> {
    Ok(uuid::Uuid::parse_str(raw)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string())
}

/// 201 when recorded, 200 for a replay; 404 when nothing was issued; 409
/// when already revoked, a request is open or the CA is retired.
pub(crate) async fn request_revocation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_application)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    // Either role may ask; the database decides (an officer, or the
    // application's own requester).
    let context = match write_context(&state, &headers, &raw_ca, &body, OFFICER_ROLE, true).await {
        Err(StatusCode::FORBIDDEN) => {
            write_context(&state, &headers, &raw_ca, &body, REQUESTER_ROLE, true).await?
        }
        other => other?,
    };
    let application_id = uuid_text(&raw_application)?;
    let request: RevocationRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !REASON_CODES.contains(&request.reason_code) || !printable(&request.reason, 500) {
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
        subject,
        ca_id.clone(),
        application_id.clone(),
        request.reason_code,
        request.reason,
        operation.clone(),
        request_sha256,
    );
    let (revocation_id, replayed) = query_db(writer_url, state.database_slots.clone(), move |db| {
        Ok(
            match db.query_one(
                "SELECT revocation_id::text, replayed FROM request_certificate_revocation_lab($1, $2, \
                 $3::text::uuid, $4::text::uuid, $5, $6, $7::text::uuid, $8)",
                &[
                    &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
                ],
            ) {
                Ok(row) => Ok((row.get::<_, String>(0), row.get::<_, bool>(1))),
                Err(error) => Err(write_status(&error)),
            },
        )
    })
    .await??;
    write_log(serde_json::json!({
        "event": "certificate_revocation_requested", "ca_id": ca_id,
        "application_id": application_id, "revocation_id": revocation_id,
        "operation_id": operation, "replayed": replayed,
    }));
    let code = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(with_replay_header(
        (
            code,
            Json(RequestResponse {
                ca_id,
                application_id,
                revocation_id,
                status: "REVOCATION_REQUESTED",
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// 201 with REVOKED (and the revocation instant) or REJECTED; 200 for a
/// replay; 403 for the requester of the revocation; 409 once decided.
pub(crate) async fn decide_revocation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_application, raw_revocation)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OFFICER_ROLE, true).await?;
    let application_id = uuid_text(&raw_application)?;
    let revocation_id = uuid_text(&raw_revocation)?;
    let request: RevocationDecision =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !matches!(request.decision.as_str(), "approve" | "reject")
        || !printable(&request.reason, 500)
    {
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
        subject,
        ca_id.clone(),
        application_id.clone(),
        revocation_id.clone(),
        request.decision,
        request.reason,
        operation.clone(),
        request_sha256,
    );
    let (status, revoked_at, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT status, revoked_at, replayed FROM decide_certificate_revocation_lab($1, \
                     $2, $3::text::uuid, $4::text::uuid, $5::text::uuid, $6, $7, $8::text::uuid, $9)",
                    &[
                        &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
                        &args.8,
                    ],
                ) {
                    Ok(row) => Ok((
                        row.get::<_, String>(0),
                        row.get::<_, Option<String>>(1),
                        row.get::<_, bool>(2),
                    )),
                    Err(error) => Err(write_status(&error)),
                },
            )
        })
        .await??;
    write_log(serde_json::json!({
        "event": "certificate_revocation_decided", "ca_id": ca_id,
        "application_id": application_id, "revocation_id": revocation_id, "status": status,
        "operation_id": operation, "replayed": replayed,
    }));
    let code = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(with_replay_header(
        (
            code,
            Json(DecisionResponse {
                ca_id,
                application_id,
                revocation_id,
                status,
                revoked_at,
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
    fn requests_refuse_unknown_fields() {
        assert!(serde_json::from_str::<RevocationRequest>(
            r#"{"reason_code":1,"reason":"x","serial":"01"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<RevocationDecision>(
            r#"{"decision":"approve","reason":"x","revoked_at":"2020-01-01T00:00:00Z"}"#
        )
        .is_err());
    }

    #[test]
    fn the_reason_codes_are_the_closed_list() {
        for code in [2, 6, 7, 8, 10, -1] {
            assert!(!REASON_CODES.contains(&code), "{code}");
        }
    }
}
