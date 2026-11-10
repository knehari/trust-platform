//! Laboratory CRL publication (migration 0031, ADR-0018, Proposed).
//!
//! `POST /v1/cas/{ca_id}/crls` (registration officer, body `{}`):
//! 1. the database allocates the CA's next CRL number and fixes the instant
//!    whose revocations the CRL lists;
//! 2. the API builds the TBS from those entries and the CA's registered
//!    issuer certificate (`trust_pki_core::application_crl`);
//! 3. the TBS digest is journaled BEFORE the signer is called; a journaled
//!    intent is never sent again;
//! 4. the laboratory signer reads the entries itself, checks the TBS,
//!    claims the intent once and signs;
//! 5. the API verifies the CRL (exact TBS, facts, issuer signature) BEFORE
//!    storing it. Any failure after the journal leaves the intent
//!    RECONCILIATION_REQUIRED, and the next CRL takes a new number.
//!
//! Readers of the CA list published CRLs (`GET /v1/cas/{ca_id}/crls`) and
//! fetch one as DER (`GET /v1/cas/{ca_id}/crls/{crl_number}`,
//! `application/pkix-crl`).

use std::path::PathBuf;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use postgres::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trust_pki_core::application_crl::{
    assemble_crl, build_crl_tbs, parse_utc_seconds, verify_crl, CrlEntry, CrlFacts,
};
use x509_cert::{
    der::{
        pem::{self, LineEnding},
        Decode, Encode,
    },
    Certificate,
};

use crate::{
    authorize,
    certificate_application::OFFICER_ROLE,
    certificate_issuance::ask_signer,
    profile_lifecycle::{with_replay_header, write_context, write_status, WriteContext},
    query_db, query_db_as, scoped_ca_id, write_log, AppState,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationRequest {}

/// Every field is always present; the PEM only on the 201 that published it.
#[derive(Serialize)]
struct PublicationResponse {
    ca_id: String,
    crl_number: i64,
    status: &'static str,
    this_update: String,
    next_update: String,
    entry_count: Option<usize>,
    crl_sha256: Option<String>,
    crl_pem: Option<String>,
}

#[derive(Serialize)]
struct PublishedCrl {
    ca_id: String,
    crl_number: i64,
    this_update: String,
    next_update: String,
    crl_sha256: String,
    published_at: String,
    entry_count: i64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Caller {
    issuer: String,
    subject: String,
    ca_id: String,
}

enum Outcome {
    Published {
        entry_count: usize,
        crl_der: Vec<u8>,
    },
    AlreadyPublished,
    Uncertain,
}

struct Begun {
    intent_id: String,
    crl_number: i64,
    this_update: String,
    next_update: String,
}

fn mark_uncertain(db: &mut Client, caller: &Caller, intent_id: &str) -> Outcome {
    // Failing to mark leaves it UNCONFIRMED: still never sent again, as the
    // journal refuses a second digest.
    let _ = db.execute(
        "SELECT mark_crl_signing_uncertain_lab($1, $2, $3::text::uuid, $4::text::uuid)",
        &[&caller.issuer, &caller.subject, &caller.ca_id, &intent_id],
    );
    Outcome::Uncertain
}

/// Runs one publication on one writer connection; each statement commits on
/// its own, so the journal exists before the signer is asked.
fn publish(
    db: &mut Client,
    caller: &Caller,
    operation: &str,
    request_sha256: &[u8],
    socket: PathBuf,
) -> Result<Result<(Begun, Outcome), StatusCode>, postgres::Error> {
    let row = match db.query_one(
        "SELECT intent_id::text, crl_number, this_update, next_update, outcome, \
         issuer_certificate_der, replayed FROM begin_crl_publication_lab($1, $2, $3::text::uuid, \
         $4::text::uuid, $5)",
        &[
            &caller.issuer,
            &caller.subject,
            &caller.ca_id,
            &operation,
            &request_sha256,
        ],
    ) {
        Ok(row) => row,
        Err(error) => return Ok(Err(write_status(&error))),
    };
    let begun = Begun {
        intent_id: row.get(0),
        crl_number: row.get(1),
        this_update: row.get(2),
        next_update: row.get(3),
    };
    match row.get::<_, String>(4).as_str() {
        "PREPARED" => {}
        "PUBLISHED" => return Ok(Ok((begun, Outcome::AlreadyPublished))),
        // A journaled intent is never sent to the signer again.
        _ => return Ok(Err(StatusCode::CONFLICT)),
    }
    let Ok(issuer) = Certificate::from_der(&row.get::<_, Vec<u8>>(5)) else {
        return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
    };
    let entries = match db.query(
        "SELECT serial, revoked_at, reason_code FROM crl_publication_entries_lab($1, $2, \
         $3::text::uuid, $4::text::uuid)",
        &[
            &caller.issuer,
            &caller.subject,
            &caller.ca_id,
            &begun.intent_id,
        ],
    ) {
        Ok(rows) => rows,
        Err(error) => return Ok(Err(write_status(&error))),
    };
    let entries = entries
        .iter()
        .map(|row| {
            Some(CrlEntry {
                serial: row.get(0),
                revoked_at: parse_utc_seconds(&row.get::<_, String>(1)).ok()?,
                reason_code: u8::try_from(row.get::<_, i16>(2)).ok()?,
            })
        })
        .collect::<Option<Vec<_>>>();
    let (Some(entries), Ok(this_update), Ok(next_update), Ok(crl_number)) = (
        entries,
        parse_utc_seconds(&begun.this_update),
        parse_utc_seconds(&begun.next_update),
        u64::try_from(begun.crl_number),
    ) else {
        return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
    };
    let facts = CrlFacts {
        crl_number,
        this_update,
        next_update,
        entries: &entries,
    };
    let Ok(tbs_der) = build_crl_tbs(&issuer, &facts).and_then(|tbs| {
        tbs.to_der()
            .map_err(|_| trust_pki_core::application_crl::CrlError::Encoding)
    }) else {
        return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
    };
    let tbs_sha256 = Sha256::digest(&tbs_der).to_vec();
    let replayed: bool = match db.query_one(
        "SELECT record_crl_signing_intent_lab($1, $2, $3::text::uuid, $4::text::uuid, $5)",
        &[
            &caller.issuer,
            &caller.subject,
            &caller.ca_id,
            &begun.intent_id,
            &tbs_sha256,
        ],
    ) {
        Ok(row) => row.get(0),
        Err(error) => return Ok(Err(write_status(&error))),
    };
    if replayed {
        return Ok(Err(StatusCode::CONFLICT));
    }
    // From here on, any failure is ambiguous: reconciliation, never a resend.
    let Some(signature) = ask_signer(&socket, Some("crl"), &begun.intent_id, &tbs_der) else {
        let outcome = mark_uncertain(db, caller, &begun.intent_id);
        return Ok(Ok((begun, outcome)));
    };
    let verified = assemble_crl(&tbs_der, &signature)
        .and_then(|der| verify_crl(&issuer, &facts, &tbs_der, &der).map(|_| der));
    let Ok(crl_der) = verified else {
        let outcome = mark_uncertain(db, caller, &begun.intent_id);
        return Ok(Ok((begun, outcome)));
    };
    if db
        .execute(
            "SELECT store_crl_lab($1, $2, $3::text::uuid, $4::text::uuid, $5)",
            &[
                &caller.issuer,
                &caller.subject,
                &caller.ca_id,
                &begun.intent_id,
                &crl_der,
            ],
        )
        .is_err()
    {
        let outcome = mark_uncertain(db, caller, &begun.intent_id);
        return Ok(Ok((begun, outcome)));
    }
    Ok(Ok((
        begun,
        Outcome::Published {
            entry_count: entries.len(),
            crl_der,
        },
    )))
}

/// The system principal of the automatic CRL renewer (migration 0035,
/// ADR-0021). The database owner grants it `crl-publisher` per CA; it can
/// only publish a CRL that is due.
pub(crate) const RENEWER_ISSUER: &str = "urn:trust-platform:system";
pub(crate) const RENEWER_SUBJECT: &str = "crl-renewer";

/// One renewal pass: publishes the CRL of every CA granted to the renewer
/// whose CRL is due, through the same journaled path as an officer.
/// Returns each CA and what happened. Never retries an ambiguous outcome:
/// the next pass takes a new CRL number.
pub(crate) async fn renew_due_crls(
    state: &AppState,
) -> Result<Vec<(String, &'static str)>, StatusCode> {
    let writer_url = state
        .writer_database_url
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let socket = state
        .signer_socket
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let outcomes = query_db(writer_url, state.database_slots.clone(), move |db| {
        let candidates: Vec<String> = db
            .query(
                "SELECT ca_id::text FROM crl_renewal_candidates_lab($1, $2)",
                &[&RENEWER_ISSUER, &RENEWER_SUBJECT],
            )?
            .iter()
            .map(|row| row.get(0))
            .collect();
        let mut outcomes = Vec::new();
        for ca_id in candidates {
            let caller = Caller {
                issuer: RENEWER_ISSUER.to_owned(),
                subject: RENEWER_SUBJECT.to_owned(),
                ca_id: ca_id.clone(),
            };
            let operation: String = db.query_one("SELECT gen_random_uuid()::text", &[])?.get(0);
            let request_sha256 =
                Sha256::digest(format!("crl-renewal:{ca_id}:{operation}")).to_vec();
            let outcome = match publish(db, &caller, &operation, &request_sha256, socket.clone())? {
                Ok((_, Outcome::Published { .. })) => "PUBLISHED",
                Ok((_, Outcome::AlreadyPublished)) => "ALREADY_PUBLISHED",
                Ok((_, Outcome::Uncertain)) => "RECONCILIATION_REQUIRED",
                Err(_) => "REFUSED",
            };
            outcomes.push((ca_id, outcome));
        }
        Ok(outcomes)
    })
    .await?;
    for (ca_id, outcome) in &outcomes {
        write_log(serde_json::json!({
            "event": "crl_auto_renewal", "ca_id": ca_id, "status": outcome,
        }));
    }
    Ok(outcomes)
}

/// Called right after a revocation or a void is recorded: a renewal pass in
/// the background, so a CA with `publish_on_revocation` (migration 0040)
/// publishes its next CRL at once. The pass publishes only what the
/// database says is due, for CAs granted to the renewer; it does nothing
/// without a writer login and a signer. The response does not wait for it.
pub(crate) fn renew_after_revocation(state: &AppState) {
    if state.writer_database_url.is_none() || state.signer_socket.is_none() {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        if renew_due_crls(&state).await.is_err() {
            write_log(serde_json::json!({
                "event": "crl_auto_renewal", "trigger": "revocation", "status": "UNAVAILABLE",
            }));
        }
    });
}

/// Runs a renewal pass shortly after startup, then every `interval`, on its
/// own thread. A failed pass is logged and retried at the next tick.
pub(crate) fn spawn_renewer(state: AppState, interval: std::time::Duration) {
    let runtime = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(5));
        loop {
            if runtime.block_on(renew_due_crls(&state)).is_err() {
                write_log(
                    serde_json::json!({"event": "crl_auto_renewal", "status": "UNAVAILABLE"}),
                );
            }
            std::thread::sleep(interval);
        }
    });
}

/// `POST /v1/cas/{ca_id}/crls`: 201 with the CRL; 200 when this key
/// published it before (no PEM); 409 for an intent already journaled; 502
/// RECONCILIATION_REQUIRED when the outcome is ambiguous; 503 without a
/// signer.
pub(crate) async fn publish_crl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let context = write_context(&state, &headers, &raw_ca, &body, OFFICER_ROLE, true).await?;
    let _: PublicationRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let socket = state
        .signer_socket
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let WriteContext {
        issuer,
        subject,
        ca_id,
        operation,
        request_sha256,
        writer_url,
    } = context;
    let caller = Caller {
        issuer,
        subject,
        ca_id: ca_id.clone(),
    };
    let log_operation = operation.clone();
    let (begun, outcome) = query_db(writer_url, state.database_slots.clone(), move |db| {
        publish(db, &caller, &operation, &request_sha256, socket)
    })
    .await??;
    let mut response = PublicationResponse {
        ca_id: ca_id.clone(),
        crl_number: begun.crl_number,
        status: "PUBLISHED",
        this_update: begun.this_update,
        next_update: begun.next_update,
        entry_count: None,
        crl_sha256: None,
        crl_pem: None,
    };
    let code = match outcome {
        Outcome::Published {
            entry_count,
            crl_der,
        } => {
            response.entry_count = Some(entry_count);
            response.crl_sha256 = Some(hex(&Sha256::digest(&crl_der)));
            response.crl_pem = pem::encode_string("X509 CRL", LineEnding::LF, &crl_der).ok();
            StatusCode::CREATED
        }
        Outcome::AlreadyPublished => StatusCode::OK,
        Outcome::Uncertain => {
            response.status = "RECONCILIATION_REQUIRED";
            StatusCode::BAD_GATEWAY
        }
    };
    write_log(serde_json::json!({
        "event": "crl_publication", "ca_id": ca_id, "crl_number": response.crl_number,
        "status": response.status, "operation_id": log_operation,
    }));
    Ok(with_replay_header(
        (code, Json(response)).into_response(),
        code == StatusCode::OK,
    ))
}

/// `GET /v1/cas/{ca_id}/crls`: published CRLs, newest first, at most 100.
pub(crate) async fn list_crls(
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
                "SELECT ca_id, crl_number, this_update, next_update, crl_sha256, published_at, \
                 entry_count FROM management_certificate_crl WHERE ca_id = $1 \
                 ORDER BY crl_number DESC LIMIT 100",
                &[&ca_id],
            )
        },
    )
    .await?;
    let items: Vec<PublishedCrl> = rows
        .into_iter()
        .map(|row| PublishedCrl {
            ca_id: row.get(0),
            crl_number: row.get(1),
            this_update: row.get(2),
            next_update: row.get(3),
            crl_sha256: row.get(4),
            published_at: row.get(5),
            entry_count: row.get(6),
        })
        .collect();
    Ok(with_replay_header(Json(items).into_response(), false))
}

#[derive(Serialize)]
struct CrlStatus {
    ca_id: String,
    distribution_point: Option<String>,
    latest_crl_number: Option<i64>,
    next_update: Option<String>,
    renewal_due: bool,
    expired: bool,
    /// Whether the automatic renewer holds this CA (migration 0035).
    auto_renewal: bool,
    /// Whether a CRL is published as soon as a revocation is recorded
    /// (migration 0040, owner-set per CA).
    publish_on_revocation: bool,
    /// Revocations and voided serials not yet on the latest published CRL.
    unpublished_entries: i64,
}

/// `GET /v1/cas/{ca_id}/crl-status`: where the CA's CRLs are published, and
/// whether the latest one must be renewed (nextUpdate within two days, or
/// no CRL yet) or has expired.
pub(crate) async fn crl_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
) -> Result<Response, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&raw_ca, &claims)?;
    let row = query_db_as(
        state.database_url,
        state.database_slots,
        (claims.iss, claims.sub),
        move |db| {
            db.query_opt(
                "SELECT ca_id, distribution_point, latest_crl_number, next_update, renewal_due, \
                 expired, auto_renewal, publish_on_revocation, unpublished_entries \
                 FROM management_crl_status WHERE ca_id = $1",
                &[&ca_id],
            )
        },
    )
    .await?
    .ok_or(StatusCode::NOT_FOUND)?;
    Ok(with_replay_header(
        Json(CrlStatus {
            ca_id: row.get(0),
            distribution_point: row.get(1),
            latest_crl_number: row.get(2),
            next_update: row.get(3),
            renewal_due: row.get(4),
            expired: row.get(5),
            auto_renewal: row.get(6),
            publish_on_revocation: row.get(7),
            unpublished_entries: row.get(8),
        })
        .into_response(),
        false,
    ))
}

/// `GET /v1/public/crls/{ca_id}/latest.crl`, WITHOUT authentication: the
/// latest published CRL of a CA whose owner configured publication
/// (migration 0032), as DER. CRLs are public by design; the view exposes
/// nothing else. 404 for any other CA, or before its first CRL.
pub(crate) async fn public_latest_crl(
    State(state): State<AppState>,
    Path(raw_ca): Path<String>,
) -> Result<Response, StatusCode> {
    let ca_id = uuid::Uuid::parse_str(&raw_ca)
        .map_err(|_| StatusCode::NOT_FOUND)?
        .to_string();
    let row = query_db(state.database_url, state.database_slots, move |db| {
        db.query_opt(
            "SELECT crl_der FROM public_crl_latest WHERE ca_id = $1",
            &[&ca_id],
        )
    })
    .await?
    .ok_or(StatusCode::NOT_FOUND)?;
    let mut response = row.get::<_, Vec<u8>>(0).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pkix-crl"),
    );
    Ok(response)
}

/// `GET /v1/cas/{ca_id}/crls/{crl_number}`: one published CRL as DER.
pub(crate) async fn read_crl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_ca, raw_number)): Path<(String, String)>,
) -> Result<Response, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&raw_ca, &claims)?;
    if raw_number.is_empty()
        || raw_number.len() > 18
        || !raw_number.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let number: i64 = raw_number.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let row = query_db_as(
        state.database_url,
        state.database_slots,
        (claims.iss, claims.sub),
        move |db| {
            db.query_opt(
                "SELECT crl_der FROM management_certificate_crl WHERE ca_id = $1 AND crl_number = $2",
                &[&ca_id, &number],
            )
        },
    )
    .await?
    .ok_or(StatusCode::NOT_FOUND)?;
    let mut response = row.get::<_, Vec<u8>>(0).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pkix-crl"),
    );
    Ok(with_replay_header(response, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_body_is_an_empty_object() {
        assert!(serde_json::from_str::<PublicationRequest>("{}").is_ok());
        assert!(serde_json::from_str::<PublicationRequest>(r#"{"crl_number":9}"#).is_err());
    }
}
