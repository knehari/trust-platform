//! Laboratory routes to activate an approved profile revision and to retire
//! the active one (migration 0024, ADR-0012, Proposed). No issuance path
//! reads the active pointer: ACTIVE authorizes no certificate yet.
//!
//! Each route requires the `trust-ca-operator` token role, the CA in scope,
//! a server-owned `ca-operator` grant and an `Idempotency-Key`. Activation
//! names the revision's exact digest. The database refuses an operator who
//! wrote, submitted or decided on the revision, a revision that is not
//! APPROVED, a policy version other than the CA's and suites the owner has
//! not declared for the CA. The API additionally requires every proposed
//! suite to be in the typed catalogue of `trust-pki-crypto`, with a
//! registered implementation, and rolls the activation back otherwise.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    profile_lifecycle::{
        decode_sha256_hex, with_replay_header, write_context, write_status, WriteContext,
    },
    query_db, valid_profile_id, valid_profile_revision, write_log, AppState,
};

pub(crate) const OPERATOR_ROLE: &str = "trust-ca-operator";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRequest {
    snapshot_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementRequest {}

#[derive(Serialize)]
struct ActivationResponse {
    ca_id: String,
    profile_id: String,
    revision: i32,
    status: String,
    /// The revision this activation superseded, if one was active.
    superseded_revision: Option<i32>,
}

/// Whether a suite identifier names an entry of the typed catalogue that has
/// a registered implementation route. A catalogue entry is not production
/// qualification, and a declared capability is not provider evidence; both
/// are required, neither is sufficient.
pub(crate) fn catalogued_suite(identifier: &str) -> bool {
    trust_pki_crypto::typed_algorithm_catalog::planned_classical_suites()
        .iter()
        .any(|record| {
            record.identifier == identifier
                && trust_pki_crypto::suite_registry::registered_backend(record.suite).is_some()
        })
}

fn path_revision(profile_id: &str, raw_revision: &str) -> Result<i32, StatusCode> {
    if !valid_profile_id(profile_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    valid_profile_revision(raw_revision)
}

/// `POST …/{revision}/activation`. 201 when activated, 200 for a replay.
pub(crate) async fn activate_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, profile_id, raw_revision)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OPERATOR_ROLE, true).await?;
    let revision = path_revision(&profile_id, &raw_revision)?;
    let request: ActivationRequest =
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
    let (status, superseded, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            let mut tx = db.transaction()?;
            let row = match tx.query_one(
                "SELECT status, superseded_revision, proposed_signature_suites, replayed \
                 FROM activate_profile_revision_lab($1, $2, $3::text::uuid, $4, $5, $6, \
                 $7::text::uuid, $8)",
                &[
                    &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
                ],
            ) {
                Ok(row) => row,
                Err(error) => return Ok(Err(write_status(&error))),
            };
            let suites: Vec<String> = row.get(2);
            // Defence in depth: the owner's declaration must name suites the
            // reviewed catalogue knows; otherwise nothing is activated.
            if !suites.iter().all(|suite| catalogued_suite(suite)) {
                tx.rollback()?;
                return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
            }
            let status: String = row.get(0);
            let superseded: Option<i32> = row.get(1);
            let replayed: bool = row.get(3);
            tx.commit()?;
            Ok(Ok((status, superseded, replayed)))
        })
        .await??;
    write_log(serde_json::json!({
        "event": "profile_revision_activated", "ca_id": ca_id, "profile_id": profile_id,
        "revision": revision, "superseded_revision": superseded,
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
            Json(ActivationResponse {
                ca_id,
                profile_id,
                revision,
                status,
                superseded_revision: superseded,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `POST …/{revision}/retirement`: ends the active revision. 201 when
/// retired, 200 for a replay.
pub(crate) async fn retire_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, profile_id, raw_revision)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OPERATOR_ROLE, true).await?;
    let revision = path_revision(&profile_id, &raw_revision)?;
    let _: RetirementRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
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
        operation.clone(),
        request_sha256,
    );
    let (status, replayed) = query_db(writer_url, state.database_slots.clone(), move |db| {
        Ok(
            match db.query_one(
                "SELECT status, replayed FROM retire_profile_revision_lab($1, $2, $3::text::uuid, \
                 $4, $5, $6::text::uuid, $7)",
                &[
                    &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6,
                ],
            ) {
                Ok(row) => Ok((row.get::<_, String>(0), row.get::<_, bool>(1))),
                Err(error) => Err(write_status(&error)),
            },
        )
    })
    .await??;
    write_log(serde_json::json!({
        "event": "profile_revision_retired", "ca_id": ca_id, "profile_id": profile_id,
        "revision": revision, "operation_id": operation, "replayed": replayed,
    }));
    let code = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(with_replay_header(
        (
            code,
            Json(ActivationResponse {
                ca_id,
                profile_id,
                revision,
                status,
                superseded_revision: None,
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
    fn only_catalogued_suite_identifiers_pass() {
        for known in ["ecdsa-p256-sha256", "rsa-pss-3072-sha384", "ed25519"] {
            assert!(catalogued_suite(known), "{known}");
        }
        for unknown in [
            "P256-SHA256",
            "ecdsa-p256-sha512",
            "ml-dsa-65",
            "",
            "ecdsa-p256-sha256 ",
        ] {
            assert!(!catalogued_suite(unknown), "{unknown}");
        }
    }

    #[test]
    fn retirement_takes_an_empty_object_only() {
        assert!(serde_json::from_str::<RetirementRequest>("{}").is_ok());
        assert!(serde_json::from_str::<RetirementRequest>(r#"{"revision":2}"#).is_err());
    }
}
