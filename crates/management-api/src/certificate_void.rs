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
//!   Since migration 0042 (ADR-0029) the confirmation is signed: the officer
//!   gets the claim from `…/void-confirmation-claims`, signs it with their
//!   registered key and sends the signature; the signer verifies it again
//!   before it lists the serial on a CRL.

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
    ca_proposal::printable,
    certificate_application::OFFICER_ROLE,
    certificate_revocation::ClaimResponse,
    profile_decision::signature_verifies,
    profile_lifecycle::{with_replay_header, write_context, write_status, WriteContext},
    query_db, write_log, AppState,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VoidRequest {
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmationRequest {
    reason: String,
    issued_at: String,
    signature_der_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

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
/// `POST …/void-confirmation-claims`: the claim the confirming officer signs
/// (migration 0042). Records nothing; 404 when no void was proposed.
pub(crate) async fn prepare_void_confirmation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_application)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OFFICER_ROLE, false).await?;
    let application_id = uuid_text(&raw_application)?;
    let _: EmptyRequest = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let WriteContext {
        issuer,
        subject,
        ca_id,
        writer_url,
        ..
    } = context;
    let (claim, key_id, issued_at) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT claim, key_id, issued_at FROM prepare_void_confirmation_lab($1, $2, \
                     $3::text::uuid, $4::text::uuid)",
                    &[&issuer, &subject, &ca_id, &application_id],
                ) {
                    Ok(row) => Ok((row.get(0), row.get(1), row.get(2))),
                    Err(error) => Err(write_status(&error)),
                },
            )
        })
        .await??;
    Ok(with_replay_header(
        Json(ClaimResponse {
            decision: "confirm".to_owned(),
            claim,
            key_id,
            issued_at,
            valid_for_seconds: 600,
        })
        .into_response(),
        false,
    ))
}

pub(crate) async fn confirm_void(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_application)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OFFICER_ROLE, true).await?;
    let application_id = uuid_text(&raw_application)?;
    let request: ConfirmationRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let issued_at = crate::valid_utc_timestamp(&request.issued_at)?;
    let signature = STANDARD
        .decode(request.signature_der_base64.trim())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if !printable(&request.reason, 500) || !(8..=80).contains(&signature.len()) {
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
        request.reason,
        issued_at,
        signature,
        operation.clone(),
        request_sha256,
    );
    let (status, serial, voided_at, replayed) = query_db(writer_url, state.database_slots.clone(), move |db| {
        let mut tx = db.transaction()?;
        let row = match tx.query_one(
            "SELECT claim, public_key_sec1, status, encode(serial, 'hex'), voided_at, replayed FROM \
             record_signed_void_confirmation_lab($1, $2, $3::text::uuid, $4::text::uuid, $5, \
             $6::text::timestamptz, $7, $8::text::uuid, $9)",
            &[&args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7, &args.8],
        ) {
            Ok(row) => row,
            Err(error) => return Ok(Err(write_status(&error))),
        };
        let claim: String = row.get(0);
        let public_key: Vec<u8> = row.get(1);
        if !signature_verifies(&public_key, &claim, &args.6) {
            tx.rollback()?;
            return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
        }
        let outcome = (
            row.get::<_, String>(2),
            row.get::<_, String>(3),
            row.get::<_, String>(4),
            row.get::<_, bool>(5),
        );
        tx.commit()?;
        Ok(Ok(outcome))
    })
    .await??;
    let serial_hex = serial;
    write_log(serde_json::json!({
        "event": "certificate_issuance_voided", "ca_id": ca_id,
        "application_id": application_id, "serial_hex": serial_hex,
        "operation_id": operation, "replayed": replayed,
    }));
    if !replayed {
        crate::crl_publication::renew_after_revocation(&state);
    }
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
