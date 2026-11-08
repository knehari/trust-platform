//! Laboratory routes for the signed two-person approval of a CA proposal
//! and its activation (migration 0027, ADR-0014, Proposed).
//!
//! A CA approver (`trust-ca-approver` role, owner-held `ca-approver`
//! platform grant, registered P-256 key) asks for the exact claim the
//! database builds for a KEY_ATTESTED proposal, signs it outside the console,
//! and sends the DER signature. The API verifies it with the key the database
//! returns, inside the recording transaction, and rolls back on failure.
//! Two approvals make the proposal APPROVED; one rejection is final.
//!
//! A CA administrator who did not decide on it then activates the APPROVED
//! proposal by naming its certificate digest. The database creates the CA
//! and its attested capability; the API verifies the stored certificate
//! again and checks the suite against the catalogue before commit. No
//! issuance path uses the new CA yet.

use std::time::SystemTime;

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
    ca_certificate::verify_lab_root,
    ca_proposal::ADMINISTRATOR_ROLE,
    profile_activation::catalogued_suite,
    profile_decision::signature_verifies,
    profile_lifecycle::{
        decode_sha256_hex, platform_write_context, with_replay_header, write_status, WriteContext,
    },
    query_db, write_log, AppState,
};

pub(crate) const CA_APPROVER_ROLE: &str = "trust-ca-approver";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    decision: String,
}

#[derive(Serialize)]
struct ClaimResponse {
    decision: String,
    claim: String,
    key_id: String,
    issued_at: String,
    /// The claim is valid for this many seconds after `issued_at`.
    valid_for_seconds: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRequest {
    decision: String,
    issued_at: String,
    signature_der_base64: String,
}

#[derive(Serialize)]
struct DecisionResponse {
    ca_id: String,
    decision: String,
    lifecycle_status: String,
    approval_count: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRequest {
    certificate_sha256: String,
}

#[derive(Serialize)]
struct ActivationResponse {
    ca_id: String,
    lifecycle_status: String,
    suite_id: String,
}

fn valid_decision(raw: &str) -> bool {
    matches!(raw, "approve" | "reject")
}

fn path_ca(raw: &str) -> Result<String, StatusCode> {
    Ok(uuid::Uuid::parse_str(raw)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string())
}

/// The stored certificate still verifies as a lab root now, and the
/// attested suite is a catalogued one with an implementation route.
fn activation_evidence_holds(certificate_der: &[u8], suite: &str, now: SystemTime) -> bool {
    verify_lab_root(certificate_der, now).is_ok() && catalogued_suite(suite)
}

fn created_or_replayed(replayed: bool) -> StatusCode {
    if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    }
}

/// `POST /v1/ca-proposals/{ca_id}/decision-claims`: returns the claim to
/// sign. Records nothing; the claim expires ten minutes after `issued_at`.
pub(crate) async fn prepare_ca_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, CA_APPROVER_ROLE, false).await?;
    let ca_id = path_ca(&raw_ca)?;
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
                    "SELECT claim, key_id, issued_at FROM prepare_ca_decision_lab($1, $2, \
                     $3::text::uuid, $4)",
                    &[&issuer, &subject, &ca_id, &decision],
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

/// `POST /v1/ca-proposals/{ca_id}/decisions`: records a signed decision.
/// 201 when recorded, 200 for a replay, 422 when the signature does not
/// verify (nothing is kept).
pub(crate) async fn record_ca_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, CA_APPROVER_ROLE, true).await?;
    let ca_id = path_ca(&raw_ca)?;
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
        request.decision.clone(),
        issued_at,
        signature,
        operation.clone(),
        request_sha256,
    );
    let (status, approval_count, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            let mut tx = db.transaction()?;
            let row = match tx.query_one(
                "SELECT claim, public_key_sec1, signature_der, lifecycle_status, approval_count, \
                 replayed FROM record_ca_decision_lab($1, $2, $3::text::uuid, $4, \
                 $5::text::timestamptz, $6, $7::text::uuid, $8)",
                &[
                    &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
                ],
            ) {
                Ok(row) => row,
                Err(error) => return Ok(Err(write_status(&error))),
            };
            let claim: String = row.get(0);
            let public_key: Vec<u8> = row.get(1);
            let signature: Vec<u8> = row.get(2);
            // The decision counts only if this approver's registered key
            // signed the exact claim the database built.
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
        "event": "ca_decision_recorded", "ca_id": ca_id, "decision": request.decision,
        "status": status, "operation_id": operation, "replayed": replayed,
    }));
    Ok(with_replay_header(
        (
            created_or_replayed(replayed),
            Json(DecisionResponse {
                ca_id,
                decision: request.decision,
                lifecycle_status: status,
                approval_count,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `POST /v1/ca-proposals/{ca_id}/activation`: creates the CA from an
/// APPROVED proposal. 201 when activated, 200 for a replay, 422 when the
/// stored certificate no longer verifies or the suite is not catalogued
/// (nothing is kept).
pub(crate) async fn activate_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, ADMINISTRATOR_ROLE, true).await?;
    let ca_id = path_ca(&raw_ca)?;
    let request: ActivationRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let digest = decode_sha256_hex(&request.certificate_sha256).ok_or(StatusCode::BAD_REQUEST)?;
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
        digest,
        operation.clone(),
        request_sha256,
    );
    let (status, suite, replayed) = query_db(writer_url, state.database_slots.clone(), move |db| {
        let mut tx = db.transaction()?;
        let row = match tx.query_one(
            "SELECT lifecycle_status, suite_id, certificate_der, replayed FROM \
                 activate_ca_lab($1, $2, $3::text::uuid, $4, $5::text::uuid, $6)",
            &[&args.0, &args.1, &args.2, &args.3, &args.4, &args.5],
        ) {
            Ok(row) => row,
            Err(error) => return Ok(Err(write_status(&error))),
        };
        let suite: String = row.get(1);
        let certificate: Vec<u8> = row.get(2);
        let replayed: bool = row.get(3);
        // The database trusts the X.509 facts the API extracted at
        // registration; check the stored bytes again before a CA exists.
        // A replay returns the recorded outcome as it was committed.
        if !replayed && !activation_evidence_holds(&certificate, &suite, SystemTime::now()) {
            tx.rollback()?;
            return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
        }
        let status: String = row.get(0);
        tx.commit()?;
        Ok(Ok((status, suite, replayed)))
    })
    .await??;
    write_log(serde_json::json!({
        "event": "ca_activated", "ca_id": ca_id, "suite_id": suite,
        "operation_id": operation, "replayed": replayed,
    }));
    Ok(with_replay_header(
        (
            created_or_replayed(replayed),
            Json(ActivationResponse {
                ca_id,
                lifecycle_status: status,
                suite_id: suite,
            }),
        )
            .into_response(),
        replayed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn activation_needs_a_current_root_and_a_catalogued_suite() {
        let pem = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/ca-root/openssl-p256-root.crt"
        ))
        .unwrap();
        let der = crate::ca_certificate::certificate_der_from_pem(&pem).unwrap();
        let in_2027 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_798_761_600);
        let in_2040 = SystemTime::UNIX_EPOCH + Duration::from_secs(2_208_988_800);
        assert!(activation_evidence_holds(
            &der,
            "ecdsa-p256-sha256",
            in_2027
        ));
        assert!(!activation_evidence_holds(
            &der,
            "ecdsa-p256-sha256",
            in_2040
        ));
        assert!(!activation_evidence_holds(&der, "p256-sha256", in_2027));
        let mut tampered = der.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(!activation_evidence_holds(
            &tampered,
            "ecdsa-p256-sha256",
            in_2027
        ));
    }

    #[test]
    fn requests_refuse_unknown_fields_and_other_decisions() {
        assert!(valid_decision("approve") && valid_decision("reject"));
        assert!(!valid_decision("activate") && !valid_decision("APPROVE"));
        assert!(serde_json::from_str::<ActivationRequest>(
            r#"{"certificate_sha256":"00","suite_id":"ecdsa-p256-sha256"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DecisionRequest>(
            r#"{"decision":"approve","issued_at":"x","signature_der_base64":"","key_id":"k"}"#
        )
        .is_err());
    }
}
