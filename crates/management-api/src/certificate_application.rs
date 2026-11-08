//! Laboratory routes for certificate applications and their registration
//! decision (migration 0029, ADR-0016, Proposed). NOTHING HERE SIGNS: an
//! APPROVED application waits for the signing slice.
//!
//! A requester (`trust-certificate-requester` role, the CA in scope, an
//! owner-held `certificate-requester` grant) submits a PKCS#10 CSR for a
//! profile, with the DNS names and validity they ask for. The API verifies
//! the CSR with the strict verifier of `trust-pki-core` (canonical DER,
//! P-256, ECDSA-SHA256, proof of possession, a subject of exactly the
//! requested CN) and passes only its facts; the database binds the
//! application to the profile's ACTIVE revision of an ACTIVE CA and checks
//! the names and validity against it. CSR extensions are never used.
//!
//! A registration officer (`trust-registration-officer` role and grant), who
//! is not the requester, approves or rejects the exact application.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trust_pki_core::csr::{verify_pkcs10_p256, CsrValidationError};
use x509_cert::{
    der::{DecodePem, Encode},
    request::CertReq,
};

use crate::{
    authorize,
    ca_proposal::printable,
    profile_lifecycle::{with_replay_header, write_context, write_status, WriteContext},
    query_db, query_db_as, scoped_ca_id, valid_profile_id, write_log, AppState,
};

pub(crate) const REQUESTER_ROLE: &str = "trust-certificate-requester";
pub(crate) const OFFICER_ROLE: &str = "trust-registration-officer";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationRequest {
    profile_id: String,
    csr_pem: String,
    common_name: String,
    dns_names: Vec<String>,
    validity_days: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRequest {
    decision: String,
    reason: String,
}

#[derive(Serialize)]
struct ApplicationResponse {
    ca_id: String,
    application_id: String,
    profile_id: String,
    revision: i32,
    status: String,
    csr_sha256: String,
}

#[derive(Serialize)]
struct DecisionResponse {
    ca_id: String,
    application_id: String,
    status: String,
}

#[derive(Serialize)]
struct Application {
    application_id: String,
    ca_id: String,
    profile_id: String,
    revision: i32,
    csr_sha256: String,
    subject_cn: String,
    dns_names: Vec<String>,
    validity_days: i32,
    status: String,
    decision_reason: Option<String>,
    submitted_at: String,
    decided_at: Option<String>,
    certificate_serial_hex: Option<String>,
    certificate_sha256: Option<String>,
    certificate_request_id: Option<String>,
    open_revocation_id: Option<String>,
    open_revocation_reason_code: Option<i16>,
    revocation_reason_code: Option<i16>,
    revoked_at: Option<String>,
}

/// A lowercase LDH DNS name of at least two labels; no wildcard. The
/// database applies the same rule and the profile's zones.
fn valid_dns_name(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    (3..=253).contains(&name.len())
        && labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn csr_der_from_pem(pem: &str) -> Option<Vec<u8>> {
    let trimmed = pem.trim();
    if trimmed.len() > 64 * 1024
        || trimmed.matches("-----BEGIN").count() != 1
        || !trimmed.starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        || !trimmed.ends_with("-----END CERTIFICATE REQUEST-----")
    {
        return None;
    }
    CertReq::from_pem(trimmed).ok()?.to_der().ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn refused(reason: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({"error": "csr_refused", "reason": reason})),
    )
        .into_response()
}

/// `POST /v1/cas/{ca_id}/certificate-applications`: 201 when recorded, 200
/// for a replay, 422 when the CSR or the request does not fit the profile.
pub(crate) async fn submit_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, REQUESTER_ROLE, true).await?;
    let request: ApplicationRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !valid_profile_id(&request.profile_id)
        || !(1..=100).contains(&request.dns_names.len())
        || !request.dns_names.iter().all(|name| valid_dns_name(name))
        || !request.dns_names.contains(&request.common_name)
        || !(1..=825).contains(&request.validity_days)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let Some(csr_der) = csr_der_from_pem(&request.csr_pem) else {
        return Ok(refused("Encoding"));
    };
    // The policy-selected CN, not the CSR, decides the subject; the CSR must
    // carry exactly it and prove possession of its key.
    let verified = match verify_pkcs10_p256(&csr_der, &request.common_name) {
        Ok(verified) => verified,
        Err(error) => {
            let reason = match error {
                CsrValidationError::SubjectMismatch => "SubjectMismatch",
                CsrValidationError::InvalidSignature => "InvalidSignature",
                CsrValidationError::UnsupportedSignatureAlgorithm
                | CsrValidationError::UnsupportedSubjectKeyAlgorithm
                | CsrValidationError::InvalidPublicKey => "UnsupportedKey",
                _ => "Encoding",
            };
            return Ok(refused(reason));
        }
    };
    let spki_sha256 = Sha256::digest(
        verified
            .subject_public_key()
            .to_der()
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?,
    )
    .to_vec();
    let WriteContext {
        issuer,
        subject,
        ca_id,
        operation,
        request_sha256,
        writer_url,
    } = context;
    let profile_id = request.profile_id.clone();
    let args = (
        issuer,
        subject,
        ca_id.clone(),
        request.profile_id,
        csr_der,
        spki_sha256,
        request.common_name,
        request.dns_names,
        request.validity_days,
        operation.clone(),
        request_sha256,
    );
    let (application_id, revision, status, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT application_id::text, revision, status, replayed FROM \
                     submit_certificate_application_lab($1, $2, $3::text::uuid, $4, $5, $6, $7, \
                     $8, $9, $10::text::uuid, $11)",
                    &[
                        &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
                        &args.8, &args.9, &args.10,
                    ],
                ) {
                    Ok(row) => Ok((
                        row.get::<_, String>(0),
                        row.get::<_, i32>(1),
                        row.get::<_, String>(2),
                        row.get::<_, bool>(3),
                    )),
                    Err(error) => Err(write_status(&error)),
                },
            )
        })
        .await??;
    write_log(serde_json::json!({
        "event": "certificate_application_submitted", "ca_id": ca_id,
        "application_id": application_id, "profile_id": profile_id, "revision": revision,
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
            Json(ApplicationResponse {
                ca_id,
                application_id,
                profile_id,
                revision,
                status,
                csr_sha256: hex(verified.fingerprint_sha256()),
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `POST /v1/cas/{ca_id}/certificate-applications/{application_id}/decision`.
pub(crate) async fn decide_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_application)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OFFICER_ROLE, true).await?;
    let application_id = uuid::Uuid::parse_str(&raw_application)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string();
    let request: DecisionRequest =
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
        request.decision,
        request.reason,
        operation.clone(),
        request_sha256,
    );
    let (status, replayed) = query_db(writer_url, state.database_slots.clone(), move |db| {
        Ok(
            match db.query_one(
                "SELECT status, replayed FROM decide_certificate_application_lab($1, $2, \
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
        "event": "certificate_application_decided", "ca_id": ca_id,
        "application_id": application_id, "status": status, "operation_id": operation,
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
            Json(DecisionResponse {
                ca_id,
                application_id,
                status,
            }),
        )
            .into_response(),
        replayed,
    ))
}

/// `GET /v1/cas/{ca_id}/certificate-applications`: newest first, at most 100,
/// for readers of the CA.
pub(crate) async fn list_applications(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
) -> Result<Response, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&raw_ca, &claims)?;
    let rows = query_db_as(
        state.database_url,
        state.database_slots,
        (claims.iss, claims.sub),
        move |db| {
            db.query(
                "SELECT application_id, ca_id, profile_id, revision, csr_sha256, subject_cn, \
                 dns_names, validity_days, status, decision_reason, submitted_at, decided_at, \
                 certificate_serial_hex, certificate_sha256, certificate_request_id, \
                 open_revocation_id, open_revocation_reason_code, revocation_reason_code, revoked_at \
                 FROM management_certificate_application WHERE ca_id = $1 \
                 ORDER BY submitted_at DESC, application_id LIMIT 100",
                &[&ca_id],
            )
        },
    )
    .await?;
    let items: Vec<Application> = rows
        .into_iter()
        .map(|row| Application {
            application_id: row.get(0),
            ca_id: row.get(1),
            profile_id: row.get(2),
            revision: row.get(3),
            csr_sha256: row.get(4),
            subject_cn: row.get(5),
            dns_names: row.get(6),
            validity_days: row.get(7),
            status: row.get(8),
            decision_reason: row.get(9),
            submitted_at: row.get(10),
            decided_at: row.get(11),
            certificate_serial_hex: row.get(12),
            certificate_sha256: row.get(13),
            certificate_request_id: row.get(14),
            open_revocation_id: row.get(15),
            open_revocation_reason_code: row.get(16),
            revocation_reason_code: row.get(17),
            revoked_at: row.get(18),
        })
        .collect();
    Ok(with_replay_header(Json(items).into_response(), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names_are_lowercase_ldh_without_wildcards() {
        for good in ["www.lab.invalid", "a.b", "x-1.lab.invalid"] {
            assert!(valid_dns_name(good), "{good}");
        }
        for bad in [
            "",
            "lab",
            "*.lab.invalid",
            "Www.lab.invalid",
            "-a.lab.invalid",
            "a-.lab.invalid",
            "a..lab.invalid",
            "a.lab.invalid.",
            "a_b.lab.invalid",
            &format!("{}.invalid", "a".repeat(64)),
        ] {
            assert!(!valid_dns_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn requests_refuse_unknown_fields() {
        assert!(serde_json::from_str::<ApplicationRequest>(
            r#"{"profile_id":"server","csr_pem":"x","common_name":"a.b","dns_names":["a.b"],"validity_days":1,"extensions":[]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DecisionRequest>(
            r#"{"decision":"approve","reason":"x","sign":true}"#
        )
        .is_err());
    }

    #[test]
    fn csr_pem_is_one_certificate_request_block() {
        assert!(csr_der_from_pem("").is_none());
        assert!(
            csr_der_from_pem("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----")
                .is_none()
        );
    }
}
