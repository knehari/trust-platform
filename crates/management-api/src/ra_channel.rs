//! The issuance channel for registration authorities (ADR-0025, Proposed;
//! boundary of ADR-0024).
//!
//! `POST /v1/ra/cas/{ca_id}/certificates` takes no OIDC token. The request
//! itself is signed by a registered RA system's P-256 key, over
//! `trust_pki_core::ra_request::ra_issuance_message`. The API:
//! 1. checks freshness and the signature with the key the database owner
//!    registered;
//! 2. verifies the CSR: proof of possession, and in a version 1 request a
//!    subject CN equal to the first name. A version 2 request (migration
//!    0041, ADR-0028) also signs the subject CN, which the RA chooses among
//!    its validated names whatever the CSR says, and optional extensions the
//!    profile allows for the CA (`client-auth`); the CSR's subject is then
//!    ignored;
//! 3. records the RA's request as a submitted and approved application under
//!    the profile's rules (migration 0038);
//! 4. issues once, through the journaled path and the separate signer
//!    (ADR-0017).
//!
//! Replaying the same signed request returns the same certificate.
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trust_pki_core::{
    application_leaf::optional_extensions_valid,
    csr::{verify_pkcs10_p256, verify_pkcs10_p256_possession, CsrValidationError},
    ra_request::{
        ra_issuance_message, ra_issuance_message_v2, ra_revocation_message, RaIssuanceRequest,
        RaIssuanceRequestV2, RaRevocationRequest,
    },
};
use x509_cert::{
    der::{pem::LineEnding, Decode, EncodePem},
    Certificate,
};

use crate::{
    certificate_application::{refused, valid_dns_name},
    certificate_issuance::{issue, Caller, Outcome},
    profile_lifecycle::write_status,
    query_db, valid_profile_id, write_log, AppState,
};

/// The principal under which an RA system is the requester of record.
pub(crate) const RA_ISSUER: &str = "urn:trust-platform:ra";
/// How far in the past `signed_at` may be from the API's clock, in seconds.
const FRESHNESS_SECONDS: i64 = 300;
/// How far in the future `signed_at` may be, in seconds (clock skew only;
/// migration 0046 applies the same bound in the database, ADR-0039).
const FUTURE_SKEW_SECONDS: i64 = 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RaIssuanceBody {
    ra_id: String,
    request_id: String,
    profile_id: String,
    csr_der_base64: String,
    /// The names the RA validated; the first is the subject CN.
    dns_names: Vec<String>,
    validity_days: u32,
    signed_at: i64,
    signature_der_base64: String,
    /// Version 2 only: the certificate's subject CN, one of `dns_names`.
    #[serde(default)]
    subject_cn: Option<String>,
    /// Version 2 only: optional extensions, in catalogue order.
    #[serde(default)]
    extensions: Option<Vec<String>>,
}

#[derive(Serialize)]
struct RaIssuanceResponse {
    ca_id: String,
    ra_id: String,
    request_id: String,
    application_id: String,
    status: &'static str,
    certificate_pem: Option<String>,
    serial_hex: Option<String>,
    certificate_sha256: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_ra_id(raw: &str) -> bool {
    (1..=63).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !raw.starts_with('-')
}

/// A UUID derived from the RA request, so a replay reuses the same issuance
/// operation (version 8, RFC 9562 custom layout).
fn issuance_operation(ra_id: &str, request_id: &str) -> String {
    let digest = Sha256::digest(format!("ra-issuance:{ra_id}:{request_id}"));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn certificate_reply(
    code: StatusCode,
    base: RaIssuanceResponse,
    der: &[u8],
) -> Result<Response, StatusCode> {
    let certificate = Certificate::from_der(der).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let serial = certificate
        .tbs_certificate
        .serial_number
        .as_bytes()
        .to_vec();
    Ok((
        code,
        Json(RaIssuanceResponse {
            status: "ISSUED",
            certificate_pem: certificate.to_pem(LineEnding::LF).ok(),
            serial_hex: Some(hex(&serial)),
            certificate_sha256: Some(hex(&Sha256::digest(der))),
            ..base
        }),
    )
        .into_response())
}

/// What happened on the database connection.
enum Done {
    Issued(Vec<u8>),
    Replayed(Vec<u8>),
    Uncertain,
    Conflict,
}

/// `POST /v1/ra/cas/{ca_id}/certificates`: 201 with the certificate; 200 with
/// the same certificate for a replay; 401 for an unknown RA, a stale request
/// or a signature that does not verify; 403 for a profile not granted; 422
/// when the CSR or the names do not fit the profile; 502 when the signing
/// outcome is ambiguous (reconciliation, ADR-0020).
pub(crate) async fn issue_for_ra(
    State(state): State<AppState>,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let request: RaIssuanceBody =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let ca_uuid = uuid::Uuid::parse_str(&raw_ca).map_err(|_| StatusCode::BAD_REQUEST)?;
    let request_uuid =
        uuid::Uuid::parse_str(&request.request_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !valid_ra_id(&request.ra_id)
        || !valid_profile_id(&request.profile_id)
        || !(1..=100).contains(&request.dns_names.len())
        || !request.dns_names.iter().all(|name| valid_dns_name(name))
        || !(1..=825).contains(&request.validity_days)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Version 2 when the RA names the subject; extensions need version 2.
    let version2 = request.subject_cn.is_some();
    let extensions = request.extensions.clone().unwrap_or_default();
    if (!version2 && request.extensions.is_some())
        || !optional_extensions_valid(&extensions)
        || request
            .subject_cn
            .as_ref()
            .is_some_and(|cn| !request.dns_names.contains(cn))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let subject_cn = request
        .subject_cn
        .clone()
        .unwrap_or_else(|| request.dns_names[0].clone());
    let csr_der = STANDARD
        .decode(request.csr_der_base64.trim())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let signature = STANDARD
        .decode(request.signature_der_base64.trim())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let writer_url = state
        .writer_database_url
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let socket = state
        .signer_socket
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let ra_id = request.ra_id.clone();
    let csr_sha256: [u8; 32] = Sha256::digest(&csr_der).into();
    let base = RaIssuanceRequest {
        ra_id: &request.ra_id,
        ca_id: *ca_uuid.as_bytes(),
        profile_id: &request.profile_id,
        request_id: *request_uuid.as_bytes(),
        csr_sha256,
        dns_names: &request.dns_names,
        validity_days: request.validity_days,
        signed_at_unix: request.signed_at,
    };
    let message = if version2 {
        ra_issuance_message_v2(&RaIssuanceRequestV2 {
            base,
            subject_cn: &subject_cn,
            extensions: &extensions,
        })
    } else {
        ra_issuance_message(&base)
    }
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    authenticate(
        &state,
        &writer_url,
        &ra_id,
        request.signed_at,
        &message,
        &signature,
    )
    .await?;

    // The RA authenticated. The CSR must prove possession of its key; in
    // version 1 it must also name exactly the first DNS name. In version 2
    // the RA signed the subject, so the CSR's is not used. CSR extensions are
    // never used.
    let verified = if version2 {
        verify_pkcs10_p256_possession(&csr_der)
    } else {
        verify_pkcs10_p256(&csr_der, &request.dns_names[0])
    };
    let verified = match verified {
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
        x509_cert::der::Encode::to_der(verified.subject_public_key())
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?,
    )
    .to_vec();

    let ca_id = ca_uuid.to_string();
    let request_id = request_uuid.to_string();
    let request_sha256 = Sha256::digest(&message).to_vec();
    let operation = issuance_operation(&ra_id, &request_id);
    let args = (
        ra_id.clone(),
        ca_id.clone(),
        request.profile_id,
        request_id.clone(),
        csr_der,
        spki_sha256,
        subject_cn,
        request.dns_names,
        i32::try_from(request.validity_days).map_err(|_| StatusCode::BAD_REQUEST)?,
        request.signed_at,
        signature,
    );
    let (application_id, done) = query_db(writer_url, state.database_slots.clone(), move |db| {
        let submitted = if version2 {
            db.query_one(
                "SELECT application_id::text, replayed FROM submit_ra_issuance_v2_lab($1, \
                 $2::text::uuid, $3, $4::text::uuid, $5, $6, $7, $8, $9, $10, $11, $12)",
                &[
                    &args.0,
                    &args.1,
                    &args.2,
                    &args.3,
                    &args.4,
                    &args.5,
                    &args.6,
                    &args.7,
                    &args.8,
                    &args.9,
                    &extensions,
                    &args.10,
                ],
            )
        } else {
            db.query_one(
                "SELECT application_id::text, replayed FROM submit_ra_issuance_lab($1, \
                 $2::text::uuid, $3, $4::text::uuid, $5, $6, $7, $8, $9, $10, $11)",
                &[
                    &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
                    &args.8, &args.9, &args.10,
                ],
            )
        };
        let submitted = match submitted {
            Ok(row) => row,
            Err(error) => return Ok(Err(write_status(&error))),
        };
        let application_id: String = submitted.get(0);
        let issued_before =
            |db: &mut postgres::Client| -> Result<Option<Vec<u8>>, postgres::Error> {
                Ok(db
                    .query_one(
                        "SELECT ra_issued_certificate_lab($1, $2::text::uuid)",
                        &[&args.0, &args.3],
                    )?
                    .get(0))
            };
        if submitted.get::<_, bool>(1) {
            if let Some(der) = issued_before(db)? {
                return Ok(Ok((application_id, Done::Replayed(der))));
            }
        }
        let caller = Caller {
            issuer: RA_ISSUER.to_owned(),
            subject: args.0.clone(),
            ca_id: args.1.clone(),
            application_id: application_id.clone(),
        };
        let done = match issue(db, &caller, &operation, &request_sha256, socket)? {
            Err(status) => return Ok(Err(status)),
            Ok(Outcome::Issued {
                certificate_der, ..
            }) => Done::Issued(certificate_der),
            Ok(Outcome::AlreadyIssued) => match issued_before(db)? {
                Some(der) => Done::Replayed(der),
                None => Done::Conflict,
            },
            Ok(Outcome::Conflict) => Done::Conflict,
            Ok(Outcome::Uncertain) => Done::Uncertain,
        };
        Ok(Ok((application_id, done)))
    })
    .await??;
    let base = RaIssuanceResponse {
        ca_id: ca_id.clone(),
        ra_id: ra_id.clone(),
        request_id: request_id.clone(),
        application_id: application_id.clone(),
        status: "RECONCILIATION_REQUIRED",
        certificate_pem: None,
        serial_hex: None,
        certificate_sha256: None,
    };
    let (status, response) = match done {
        Done::Issued(der) => (
            "ISSUED",
            certificate_reply(StatusCode::CREATED, base, &der)?,
        ),
        Done::Replayed(der) => ("REPLAYED", certificate_reply(StatusCode::OK, base, &der)?),
        Done::Conflict => ("CONFLICT", StatusCode::CONFLICT.into_response()),
        Done::Uncertain => (
            "RECONCILIATION_REQUIRED",
            (StatusCode::BAD_GATEWAY, Json(base)).into_response(),
        ),
    };
    write_log(serde_json::json!({
        "event": "ra_issuance", "ca_id": ca_id, "ra_id": ra_id, "request_id": request_id,
        "application_id": application_id, "status": status,
    }));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ra_ids_and_operations_are_strict_and_stable() {
        assert!(valid_ra_id("lab-ra"));
        for bad in ["", "-ra", "Lab", "ra_1", "ra.1", &"a".repeat(64)] {
            assert!(!valid_ra_id(bad), "{bad}");
        }
        let a = issuance_operation("lab-ra", "11111111-1111-4111-8111-111111111111");
        assert_eq!(
            a,
            issuance_operation("lab-ra", "11111111-1111-4111-8111-111111111111")
        );
        assert_ne!(
            a,
            issuance_operation("lab-rb", "11111111-1111-4111-8111-111111111111")
        );
        let parsed = uuid::Uuid::parse_str(&a).unwrap();
        assert_eq!(parsed.get_version_num(), 8);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RaRevocationBody {
    ra_id: String,
    request_id: String,
    /// The certificate's serial, lowercase or uppercase hexadecimal.
    serial_hex: String,
    reason_code: u16,
    reason: String,
    signed_at: i64,
    signature_der_base64: String,
}

#[derive(Serialize)]
struct RaRevocationResponse {
    ca_id: String,
    ra_id: String,
    request_id: String,
    serial_hex: String,
    revocation_id: String,
    status: &'static str,
    revoked_at: Option<String>,
}

/// Freshness, the registered key and the signature over `message`: 401 on
/// any failure, before the request reaches the database functions.
async fn authenticate(
    state: &AppState,
    writer_url: &str,
    ra_id: &str,
    signed_at: i64,
    message: &[u8],
    signature: &[u8],
) -> Result<(), StatusCode> {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .as_secs(),
    )
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if now - signed_at > FRESHNESS_SECONDS || signed_at - now > FUTURE_SKEW_SECONDS {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let lookup = ra_id.to_owned();
    let key: Option<Vec<u8>> = query_db(
        writer_url.to_owned(),
        state.database_slots.clone(),
        move |db| {
            Ok(db
                .query_one("SELECT ra_system_key_lab($1)", &[&lookup])?
                .get(0))
        },
    )
    .await?;
    let Some(key) = key else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if trust_pki_crypto::verify_p256_ecdsa_sha256(&key, message, signature).is_err() {
        write_log(serde_json::json!({
            "event": "ra_request", "ra_id": ra_id, "status": "BAD_SIGNATURE",
        }));
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn serial_bytes(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.trim().to_ascii_lowercase();
    if raw.is_empty() || raw.len() > 40 || raw.len() % 2 != 0 {
        return None;
    }
    (0..raw.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(raw.get(index..index + 2)?, 16).ok())
        .collect()
}

/// `POST /v1/ra/cas/{ca_id}/revocations` (ADR-0026): revokes a certificate
/// the signing RA obtained through the channel. 201 when revoked; 200 for a
/// replay of the same signed request; 401 for an unknown RA, a stale request
/// or a bad signature; 404 when this RA obtained no certificate with that
/// serial; 409 when already revoked, a request is open, the request id was
/// used for other bytes, or the CA is retired.
pub(crate) async fn revoke_for_ra(
    State(state): State<AppState>,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let request: RaRevocationBody =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let ca_uuid = uuid::Uuid::parse_str(&raw_ca).map_err(|_| StatusCode::BAD_REQUEST)?;
    let request_uuid =
        uuid::Uuid::parse_str(&request.request_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let serial = serial_bytes(&request.serial_hex).ok_or(StatusCode::BAD_REQUEST)?;
    if !valid_ra_id(&request.ra_id)
        || request.reason_code > 10
        || request.reason.is_empty()
        || request.reason.chars().count() > 500
        || request.reason.chars().any(char::is_control)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let signature = STANDARD
        .decode(request.signature_der_base64.trim())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let writer_url = state
        .writer_database_url
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let message = ra_revocation_message(&RaRevocationRequest {
        ra_id: &request.ra_id,
        ca_id: *ca_uuid.as_bytes(),
        request_id: *request_uuid.as_bytes(),
        serial: &serial,
        reason_code: request.reason_code,
        reason: &request.reason,
        signed_at_unix: request.signed_at,
    })
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    authenticate(
        &state,
        &writer_url,
        &request.ra_id,
        request.signed_at,
        &message,
        &signature,
    )
    .await?;

    let ca_id = ca_uuid.to_string();
    let request_id = request_uuid.to_string();
    let reason_code = i16::try_from(request.reason_code).map_err(|_| StatusCode::BAD_REQUEST)?;
    let args = (
        request.ra_id.clone(),
        ca_id.clone(),
        request_id.clone(),
        serial.clone(),
        reason_code,
        request.reason,
        request.signed_at,
        signature,
    );
    let (revocation_id, revoked_at, replayed) =
        query_db(writer_url, state.database_slots.clone(), move |db| {
            Ok(
                match db.query_one(
                    "SELECT revocation_id::text, revoked_at, replayed FROM submit_ra_revocation_lab($1, \
                     $2::text::uuid, $3::text::uuid, $4, $5, $6, $7, $8)",
                    &[
                        &args.0, &args.1, &args.2, &args.3, &args.4, &args.5, &args.6, &args.7,
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
    let serial_hex = hex(&serial);
    write_log(serde_json::json!({
        "event": "ra_revocation", "ca_id": ca_id, "ra_id": request.ra_id,
        "request_id": request_id, "serial_hex": serial_hex,
        "status": if replayed { "REPLAYED" } else { "REVOKED" },
    }));
    // The worker's next renewal pass publishes the CRL when due (ADR-0037).
    let code = if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        code,
        Json(RaRevocationResponse {
            ca_id,
            ra_id: request.ra_id,
            request_id,
            serial_hex,
            revocation_id,
            status: "REVOKED",
            revoked_at,
        }),
    )
        .into_response())
}
