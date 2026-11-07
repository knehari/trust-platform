//! Laboratory routes for signed decisions on submitted profile revisions
//! (migration 0023, ADR-0011, Proposed). Two distinct approvers, each with a
//! registered P-256 key, approve a revision; one rejection ends it. APPROVED
//! has no effect on issuance.
//!
//! An approver first asks for the decision claim, the exact one-line text the
//! database builds for this revision, approver, key and time. The approver
//! signs it outside the console with their own key (for example
//! `openssl dgst -sha256 -sign`), then sends the DER signature. The API
//! records the decision and verifies the signature against the claim and key
//! the database returns, inside the same transaction: a signature that does
//! not verify rolls the decision back (422).

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
    profile_lifecycle::{with_replay_header, write_context, write_status, WriteContext},
    query_db, valid_profile_id, valid_profile_revision, write_log, AppState,
};

pub(crate) const APPROVER_ROLE: &str = "trust-policy-approver";

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
    profile_id: String,
    revision: i32,
    decision: String,
    status: String,
    approval_count: i32,
}

fn valid_decision(raw: &str) -> bool {
    matches!(raw, "approve" | "reject")
}

/// Verifies an approver's DER ECDSA P-256/SHA-256 signature over the exact
/// claim bytes with the registered key. Uses the reviewed `p256` verifier of
/// `trust-pki-crypto`; no primitive is implemented here.
pub(crate) fn signature_verifies(
    public_key_sec1: &[u8],
    claim: &str,
    signature_der: &[u8],
) -> bool {
    trust_pki_crypto::canonical_p256_public_key_sec1(public_key_sec1).is_ok()
        && trust_pki_crypto::verify_p256_ecdsa_sha256(
            public_key_sec1,
            claim.as_bytes(),
            signature_der,
        )
        .is_ok()
}

fn path_parts(profile_id: &str, raw_revision: &str) -> Result<i32, StatusCode> {
    if !valid_profile_id(profile_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    valid_profile_revision(raw_revision)
}

/// `POST …/{revision}/decision-claims`: returns the claim to sign. Records
/// nothing; the claim expires ten minutes after `issued_at`.
pub(crate) async fn prepare_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, profile_id, raw_revision)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, APPROVER_ROLE, false).await?;
    let revision = path_parts(&profile_id, &raw_revision)?;
    let request: ClaimRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !valid_decision(&request.decision) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let WriteContext {
        issuer,
        subject,
        ca_id,
        writer_url,
        ..
    } = context;
    let decision = request.decision.clone();
    let (claim, key_id, issued_at) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT claim, key_id, issued_at FROM prepare_profile_decision_lab(\
                 $1, $2, $3::text::uuid, $4, $5, $6)",
                    &[&issuer, &subject, &ca_id, &profile_id, &revision, &decision],
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

/// `POST …/{revision}/decisions`: records a signed decision. 201 when
/// recorded, 200 for a replay of the same Idempotency-Key and body.
pub(crate) async fn record_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, profile_id, raw_revision)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, APPROVER_ROLE, true).await?;
    let revision = path_parts(&profile_id, &raw_revision)?;
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
        request.decision.clone(),
        issued_at,
        signature,
        operation.clone(),
        request_sha256,
    );
    let outcome = query_db(writer_url, state.database_slots.clone(), move |db| {
        let mut tx = db.transaction()?;
        let row = match tx.query_one(
            "SELECT claim, public_key_sec1, signature_der, lifecycle_status, approval_count, replayed \
             FROM record_profile_decision_lab($1, $2, $3::text::uuid, $4, $5, $6, $7::text::timestamptz, \
             $8, $9::text::uuid, $10)",
            &[
                &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7, &args.8,
                &args.9,
            ],
        ) {
            Ok(row) => row,
            Err(error) => return Ok(Err(write_status(&error))),
        };
        let claim: String = row.get(0);
        let public_key: Vec<u8> = row.get(1);
        let signature: Vec<u8> = row.get(2);
        // The decision counts only if this approver's registered key signed
        // the exact claim the database built. Otherwise nothing is kept.
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
    let (status, approval_count, replayed) = outcome;
    write_log(serde_json::json!({
        "event": "profile_decision_recorded", "ca_id": ca_id, "profile_id": profile_id,
        "revision": revision, "decision": request.decision, "status": status,
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
                profile_id,
                revision,
                decision: request.decision,
                status,
                approval_count,
            }),
        )
            .into_response(),
        replayed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    #[test]
    fn only_the_registered_key_over_the_exact_claim_verifies() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let public = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let claim = "trust-platform/profile-decision/v1;decision=approve;revision=1";
        let signature: Signature = key.sign(claim.as_bytes());
        let der = signature.to_der().as_bytes().to_vec();
        assert!(signature_verifies(&public, claim, &der));
        assert!(!signature_verifies(
            &public,
            &claim.replace("approve", "reject"),
            &der
        ));
        let forged: Signature = other.sign(claim.as_bytes());
        assert!(!signature_verifies(
            &public,
            claim,
            forged.to_der().as_bytes()
        ));
        assert!(!signature_verifies(&public[..64], claim, &der));
        assert!(!signature_verifies(&public, claim, &der[..der.len() - 1]));
    }

    #[test]
    fn decisions_are_approve_or_reject_only() {
        assert!(valid_decision("approve") && valid_decision("reject"));
        for other in ["APPROVE", "activate", "", "approve "] {
            assert!(!valid_decision(other));
        }
        assert!(serde_json::from_str::<DecisionRequest>(
            r#"{"decision":"approve","issued_at":"x","signature_der_base64":"","key_id":"k"}"#
        )
        .is_err());
    }
}
