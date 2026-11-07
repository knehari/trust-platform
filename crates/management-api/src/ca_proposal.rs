//! Laboratory routes to propose a CA and register its self-signed issuer
//! certificate (migration 0025, ADR-0013, Proposed). A proposal is not a CA:
//! nothing here creates a `ca` row, approves, activates or issues.
//!
//! Each route requires the `trust-ca-administrator` token role; the database
//! then requires a server-owned `ca-administrator` platform grant for the
//! same issuer and subject. The private key is generated outside the
//! platform; the API receives only the certificate, verifies it
//! (`ca_certificate`) and passes the extracted facts to the database, which
//! checks them against the proposal.

use std::time::SystemTime;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    authenticate,
    ca_certificate::{certificate_der_from_pem, verify_lab_root, RootRejection},
    profile_lifecycle::{platform_write_context, with_replay_header, write_status, WriteContext},
    query_db, query_db_as, write_log, AppState,
};

pub(crate) const ADMINISTRATOR_ROLE: &str = "trust-ca-administrator";
/// The only suite a lab CA can be proposed with: its key type is the one
/// the certificate check and the database map (P-256).
pub(crate) const PROPOSABLE_SUITE: &str = "ecdsa-p256-sha256";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalRequest {
    display_name: String,
    policy_version: String,
    suite_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateRequest {
    certificate_pem: String,
}

#[derive(Serialize)]
struct ProposalResponse {
    ca_id: String,
    lifecycle_status: &'static str,
    proposed_at: String,
}

#[derive(Serialize)]
struct CertificateResponse {
    ca_id: String,
    lifecycle_status: String,
    certificate_sha256: String,
}

#[derive(Serialize)]
struct CaProposal {
    ca_id: String,
    display_name: String,
    policy_version: String,
    suite_id: String,
    lifecycle_status: String,
    proposed_at: String,
    certificate_sha256: Option<String>,
    spki_sha256: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    custody: Option<String>,
    registered_at: Option<String>,
}

fn printable(value: &str, max_chars: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn rejection_body(reason: RootRejection) -> Response {
    let reason = format!("{reason:?}");
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({"error": "certificate_refused", "reason": reason})),
    )
        .into_response()
}

/// `POST /v1/ca-proposals`: records a PROPOSED CA. 201 when recorded, 200
/// for a replay.
pub(crate) async fn propose_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, ADMINISTRATOR_ROLE).await?;
    let request: ProposalRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !printable(&request.display_name, 255) || !printable(&request.policy_version, 128) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if request.suite_id != PROPOSABLE_SUITE {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
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
        request.display_name,
        request.policy_version,
        request.suite_id,
        operation.clone(),
        request_sha256,
    );
    let (ca_id, proposed_at, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT ca_id::text, proposed_at, replayed FROM propose_ca_lab($1, $2, NULL, \
                     $3, $4, $5, $6::text::uuid, $7)",
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
        "event": "ca_proposed", "ca_id": ca_id, "operation_id": operation, "replayed": replayed,
    }));
    let code = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(with_replay_header(
        (
            code,
            Json(ProposalResponse {
                ca_id,
                lifecycle_status: "PROPOSED",
                proposed_at,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `POST /v1/ca-proposals/{ca_id}/issuer-certificate`: verifies and records
/// the proposal's self-signed root. 201 when recorded (KEY_ATTESTED), 200
/// for a replay, 422 with a reason when the certificate is refused.
pub(crate) async fn register_issuer_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = platform_write_context(&state, &headers, &body, ADMINISTRATOR_ROLE).await?;
    let ca_id = uuid::Uuid::parse_str(&raw_ca)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string();
    let request: CertificateRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let root = match certificate_der_from_pem(&request.certificate_pem)
        .and_then(|der| verify_lab_root(&der, SystemTime::now()))
    {
        Ok(root) => root,
        Err(reason) => return Ok(rejection_body(reason)),
    };
    let WriteContext {
        issuer,
        subject,
        operation,
        request_sha256,
        writer_url,
        ..
    } = context;
    let spki = root.spki_sha256.to_vec();
    let args = (
        issuer,
        subject,
        ca_id.clone(),
        root.der,
        spki,
        root.subject_cn,
        root.not_before,
        root.not_after,
        operation.clone(),
        request_sha256,
    );
    let (status, certificate_sha256, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT state, certificate_sha256, replayed FROM \
                     register_ca_issuer_certificate_lab($1, $2, $3::text::uuid, $4, $5, $6, $7, \
                     $8, 'p256', $9::text::uuid, $10)",
                    &[
                        &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
                        &args.8, &args.9,
                    ],
                ) {
                    Ok(row) => Ok((
                        row.get::<_, String>(0),
                        row.get::<_, Vec<u8>>(1),
                        row.get::<_, bool>(2),
                    )),
                    Err(error) => Err(write_status(&error)),
                },
            )
        })
        .await??;
    write_log(serde_json::json!({
        "event": "ca_issuer_certificate_registered", "ca_id": ca_id,
        "certificate_sha256": hex(&certificate_sha256), "operation_id": operation,
        "replayed": replayed,
    }));
    let code = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(with_replay_header(
        (
            code,
            Json(CertificateResponse {
                ca_id,
                lifecycle_status: status,
                certificate_sha256: hex(&certificate_sha256),
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `GET /v1/ca-proposals`: the proposals, newest first (at most 100), for a
/// token with the administrator role. The view returns rows only when the
/// declared principal holds the platform grant.
pub(crate) async fn list_ca_proposals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let claims = authenticate(&headers, &state.verifier).await?;
    if !claims.roles.iter().any(|role| role == ADMINISTRATOR_ROLE) {
        return Err(StatusCode::FORBIDDEN);
    }
    let rows = query_db_as(
        state.database_url,
        state.database_slots,
        (claims.iss, claims.sub),
        |db| {
            db.query(
                "SELECT ca_id, display_name, policy_version, suite_id, lifecycle_status, \
                 proposed_at, certificate_sha256, spki_sha256, not_before, not_after, custody, \
                 registered_at FROM management_ca_proposal \
                 ORDER BY proposed_at DESC, ca_id LIMIT 100",
                &[],
            )
        },
    )
    .await?;
    let items: Vec<CaProposal> = rows
        .into_iter()
        .map(|row| CaProposal {
            ca_id: row.get(0),
            display_name: row.get(1),
            policy_version: row.get(2),
            suite_id: row.get(3),
            lifecycle_status: row.get(4),
            proposed_at: row.get(5),
            certificate_sha256: row.get(6),
            spki_sha256: row.get(7),
            not_before: row.get(8),
            not_after: row.get(9),
            custody: row.get(10),
            registered_at: row.get(11),
        })
        .collect();
    Ok(with_replay_header(Json(items).into_response(), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_refuse_unknown_fields() {
        assert!(serde_json::from_str::<ProposalRequest>(
            r#"{"display_name":"A","policy_version":"v1","suite_id":"ecdsa-p256-sha256","ca_id":"x"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CertificateRequest>(
            r#"{"certificate_pem":"x","private_key_pem":"y"}"#
        )
        .is_err());
    }

    #[test]
    fn names_are_printable_and_trimmed() {
        assert!(printable("Trust Lab Root", 255));
        for bad in ["", " Root", "Root ", "Ro\not", &"x".repeat(256)] {
            assert!(!printable(bad, 255), "{bad:?}");
        }
    }

    #[test]
    fn only_the_p256_suite_is_proposable_and_catalogued() {
        assert!(crate::profile_activation::catalogued_suite(
            PROPOSABLE_SUITE
        ));
    }
}
