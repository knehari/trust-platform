//! Laboratory reconciliation of an ambiguous application issuance by voiding
//! its serial under dual control (migration 0034, ADR-0020, Proposed).
//!
//! - `POST /v1/cas/{ca_id}/certificate-applications/{id}/void-proposal`: a
//!   registration officer who is not the application's requester proposes to
//!   void an issuance left `RECONCILIATION_REQUIRED`, with a reason. The
//!   database records whether the signer had claimed the intent.
//! - `POST …/void-confirmation`: a different officer confirms, once. The
//!   application becomes `VOIDED`, and the serial is listed on every CRL
//!   whose intent is fixed afterwards. It is never re-signed or reused.

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
    certificate_application::OFFICER_ROLE,
    profile_lifecycle::{with_replay_header, write_context, write_status, WriteContext},
    query_db, write_log, AppState,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VoidRequest {
    reason: String,
}

#[derive(Serialize)]
struct ProposalResponse {
    ca_id: String,
    application_id: String,
    status: String,
    void_status: &'static str,
    signer_claimed: bool,
}

#[derive(Serialize)]
struct ConfirmationResponse {
    ca_id: String,
    application_id: String,
    status: String,
    serial_hex: String,
    voided_at: String,
}

fn uuid_text(raw: &str) -> Result<String, StatusCode> {
    Ok(uuid::Uuid::parse_str(raw)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string())
}

fn reason(body: &Bytes) -> Result<String, StatusCode> {
    let request: VoidRequest = serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !printable(&request.reason, 500) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(request.reason)
}

fn created(replayed: bool) -> StatusCode {
    if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    }
}

/// 201 when recorded, 200 for a replay; 403 for a non-officer or the
/// requester; 404 when nothing was issued; 409 when the issuance is not
/// ambiguous or a void was already proposed.
pub(crate) async fn propose_void(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_application)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OFFICER_ROLE, true).await?;
    let application_id = uuid_text(&raw_application)?;
    let reason = reason(&body)?;
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
        reason,
        operation.clone(),
        request_sha256,
    );
    let (status, signer_claimed, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(match db.query_one(
            "SELECT status, signer_claimed, replayed FROM propose_application_void_lab($1, $2, \
             $3::text::uuid, $4::text::uuid, $5, $6::text::uuid, $7)",
            &[&args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6],
        ) {
            Ok(row) => Ok((row.get::<_, String>(0), row.get::<_, bool>(1), row.get::<_, bool>(2))),
            Err(error) => Err(write_status(&error)),
        })
        })
        .await??;
    write_log(serde_json::json!({
        "event": "certificate_issuance_void_proposed", "ca_id": ca_id,
        "application_id": application_id, "signer_claimed": signer_claimed,
        "operation_id": operation, "replayed": replayed,
    }));
    Ok(with_replay_header(
        (
            created(replayed),
            Json(ProposalResponse {
                ca_id,
                application_id,
                status,
                void_status: "PROPOSED",
                signer_claimed,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// 201 with VOIDED, the serial and the instant; 200 for a replay; 403 for a
/// non-officer, the requester or the proposer; 404 when nothing was
/// proposed; 409 once voided.
pub(crate) async fn confirm_void(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_application)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OFFICER_ROLE, true).await?;
    let application_id = uuid_text(&raw_application)?;
    let reason = reason(&body)?;
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
        reason,
        operation.clone(),
        request_sha256,
    );
    let (status, serial, voided_at, replayed) = query_db(writer_url, state.database_slots.clone(), move |db| {
        Ok(match db.query_one(
            "SELECT status, encode(serial, 'hex'), voided_at, replayed FROM confirm_application_void_lab($1, $2, \
             $3::text::uuid, $4::text::uuid, $5, $6::text::uuid, $7)",
            &[&args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6],
        ) {
            Ok(row) => Ok((
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
                row.get::<_, bool>(3),
            )),
            Err(error) => Err(write_status(&error)),
        })
    })
    .await??;
    let serial_hex = serial;
    write_log(serde_json::json!({
        "event": "certificate_issuance_voided", "ca_id": ca_id,
        "application_id": application_id, "serial_hex": serial_hex,
        "operation_id": operation, "replayed": replayed,
    }));
    Ok(with_replay_header(
        (
            created(replayed),
            Json(ConfirmationResponse {
                ca_id,
                application_id,
                status,
                serial_hex,
                voided_at,
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
    fn void_requests_need_a_printable_reason_and_nothing_else() {
        assert!(reason(&Bytes::from_static(br#"{"reason":"signer timed out"}"#)).is_ok());
        assert_eq!(
            reason(&Bytes::from_static(br#"{"reason":""}"#)),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            reason(&Bytes::from_static(br#"{"reason":"x","serial":"01"}"#)),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            reason(&Bytes::from_static(br#"{}"#)),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            reason(&Bytes::from_static(b"{\"reason\":\"a\\u0007b\"}")),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn replays_answer_200_and_first_writes_201() {
        assert_eq!(created(true), StatusCode::OK);
        assert_eq!(created(false), StatusCode::CREATED);
    }
}
