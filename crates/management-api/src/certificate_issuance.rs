//! Laboratory issuance of approved certificate applications (migration
//! 0029, ADR-0017, Proposed).
//!
//! `POST /v1/cas/{ca_id}/certificate-applications/{id}/issuance` runs the
//! core orchestrator (`trust_pki_core::orchestrator::issue_once`):
//! 1. the database starts the core request and reserves a serial;
//! 2. the API builds the server leaf TBS from the CA's registered issuer
//!    certificate and the application's verified facts;
//! 3. the durable signing intent with the TBS digest is committed BEFORE the
//!    signer is called; an existing intent is never signed again;
//! 4. the separate laboratory signer (Unix socket) checks everything again
//!    on its own, claims the intent once and signs;
//! 5. the API verifies the certificate independently (exact journaled TBS,
//!    the leaf rules, the issuer key's signature) BEFORE persisting it.
//!
//! Any failure after the intent leaves RECONCILIATION_REQUIRED: the outcome
//! is ambiguous and is never re-signed. The API never holds a CA key.

use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    rc::Rc,
    time::{Duration, SystemTime},
};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use postgres::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trust_pki_core::{
    application_leaf::{
        assemble_certificate, build_server_leaf_tbs, verify_server_leaf, LeafFacts,
    },
    csr::verify_pkcs10_p256,
    orchestrator::{
        issue_once, CertificateAssembler, CertificateVerifier, ExternalSigner, IssuanceJournal,
        IssuancePlan, IssueError,
    },
};
use x509_cert::{
    der::{pem::LineEnding, Decode, Encode, EncodePem},
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::{
    certificate_application::{OFFICER_ROLE, REQUESTER_ROLE},
    profile_lifecycle::{with_replay_header, write_context, write_status, WriteContext},
    query_db, write_log, AppState,
};

/// How long the API waits for the signer before the outcome is ambiguous.
const SIGNER_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuanceRequest {}

#[derive(Serialize)]
/// Every field is always present; the certificate only on the 201 that issued it.
struct IssuanceResponse {
    ca_id: String,
    application_id: String,
    status: &'static str,
    certificate_pem: Option<String>,
    serial_hex: Option<String>,
    certificate_sha256: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The parameters every issuance function takes.
struct Caller {
    issuer: String,
    subject: String,
    ca_id: String,
    application_id: String,
}

/// The durable journal: the 0029 wrappers over the core functions. Each call
/// is its own committed statement, so the intent exists before signing.
struct Journal<'a> {
    db: &'a mut Client,
    caller: &'a Caller,
    intent_id: Rc<RefCell<Option<String>>>,
    facts: &'a OwnedFacts,
}

impl IssuanceJournal for Journal<'_> {
    fn record_intent(
        &mut self,
        plan: &IssuancePlan<'_>,
        tbs_sha256: &[u8; 32],
    ) -> Result<(), IssueError> {
        let c = self.caller;
        let row = self
            .db
            .query_one(
                "SELECT intent_id::text, replayed FROM record_application_signing_intent_lab($1, \
                 $2, $3::text::uuid, $4::text::uuid, $5, $6)",
                &[
                    &c.issuer,
                    &c.subject,
                    &c.ca_id,
                    &c.application_id,
                    &plan.signer_key_ref,
                    &tbs_sha256.as_slice(),
                ],
            )
            .map_err(|_| IssueError::JournalFailure)?;
        // An intent recorded before is never signed again.
        if row.get::<_, bool>(1) {
            return Err(IssueError::ReplayedOrAmbiguousIntent);
        }
        *self.intent_id.borrow_mut() = Some(row.get(0));
        Ok(())
    }

    fn mark_uncertain(&mut self, _plan: &IssuancePlan<'_>) -> Result<(), IssueError> {
        let c = self.caller;
        self.db
            .execute(
                "SELECT mark_application_signing_uncertain_lab($1, $2, $3::text::uuid, \
                 $4::text::uuid)",
                &[&c.issuer, &c.subject, &c.ca_id, &c.application_id],
            )
            .map(|_| ())
            .map_err(|_| IssueError::JournalFailure)
    }

    fn persist_verified(
        &mut self,
        _plan: &IssuancePlan<'_>,
        tbs_sha256: &[u8; 32],
        _certificate_sha256: &[u8; 32],
        certificate_der: &[u8],
    ) -> Result<(), IssueError> {
        let certificate =
            Certificate::from_der(certificate_der).map_err(|_| IssueError::PersistenceFailure)?;
        let validity = &certificate.tbs_certificate.validity;
        let utc = |time: &x509_cert::time::Time| {
            let value = time.to_date_time();
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                value.year(),
                value.month(),
                value.day(),
                value.hour(),
                value.minutes(),
                value.seconds()
            )
        };
        let names = certificate_dns_names(&certificate).ok_or(IssueError::PersistenceFailure)?;
        let c = self.caller;
        self.db
            .execute(
                "SELECT store_application_certificate_lab($1, $2, $3::text::uuid, $4::text::uuid, \
                 $5, $6, $7, $8, $9, $10)",
                &[
                    &c.issuer,
                    &c.subject,
                    &c.ca_id,
                    &c.application_id,
                    &tbs_sha256.as_slice(),
                    &certificate_der,
                    &self.facts.subject_cn,
                    &utc(&validity.not_before),
                    &utc(&validity.not_after),
                    &names,
                ],
            )
            .map(|_| ())
            .map_err(|_| IssueError::PersistenceFailure)
    }
}

fn certificate_dns_names(certificate: &Certificate) -> Option<Vec<String>> {
    let extension = certificate
        .tbs_certificate
        .extensions
        .as_deref()?
        .iter()
        .find(|extension| extension.extn_id.to_string() == "2.5.29.17")?;
    let san = SubjectAltName::from_der(extension.extn_value.as_bytes()).ok()?;
    san.0
        .iter()
        .map(|name| match name {
            GeneralName::DnsName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect()
}

/// The laboratory signer, over its Unix socket. It decides on its own.
struct SocketSigner {
    socket: PathBuf,
    intent_id: Rc<RefCell<Option<String>>>,
}

impl ExternalSigner for SocketSigner {
    fn sign_once(
        &mut self,
        _key_ref: &str,
        _operation_ref: &str,
        tbs_der: &[u8],
    ) -> Result<Vec<u8>, IssueError> {
        let intent = self
            .intent_id
            .borrow()
            .clone()
            .ok_or(IssueError::SigningFailure)?;
        ask_signer(&self.socket, None, &intent, tbs_der).ok_or(IssueError::SigningFailure)
    }
}

/// One request to the laboratory signer: the intent and the exact TBS. Any
/// failure, refusal or timeout is `None`; the caller treats it as ambiguous.
pub(crate) fn ask_signer(
    socket: &std::path::Path,
    kind: Option<&str>,
    intent_id: &str,
    tbs_der: &[u8],
) -> Option<Vec<u8>> {
    let stream = UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(SIGNER_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(SIGNER_TIMEOUT)).ok()?;
    let mut request =
        serde_json::json!({"intent_id": intent_id, "tbs_der_base64": STANDARD.encode(tbs_der)});
    if let Some(kind) = kind {
        request["kind"] = serde_json::Value::from(kind);
    }
    writeln!(&stream, "{request}").ok()?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).ok()?;
    let reply: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    STANDARD
        .decode(reply["signature_der_base64"].as_str()?)
        .ok()
}

struct Assembler;
impl CertificateAssembler for Assembler {
    fn assemble(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>, IssueError> {
        assemble_certificate(tbs_der, signature).map_err(|_| IssueError::AssemblyFailure)
    }
}

/// The application's facts, owned, and the parsed issuer certificate.
struct OwnedFacts {
    subject_cn: String,
    dns_names: Vec<String>,
    validity_days: u32,
    serial: Vec<u8>,
    subject_public_key: x509_cert::spki::SubjectPublicKeyInfoOwned,
    issuer: Certificate,
    crl_distribution_point: Option<String>,
}

impl OwnedFacts {
    fn leaf(&self) -> LeafFacts<'_> {
        LeafFacts {
            subject_cn: &self.subject_cn,
            dns_names: &self.dns_names,
            subject_public_key: &self.subject_public_key,
            validity_days: self.validity_days,
            serial: &self.serial,
            crl_distribution_point: self.crl_distribution_point.as_deref(),
        }
    }
}

/// Independent verification before persistence.
struct Verifier<'a> {
    facts: &'a OwnedFacts,
}
impl CertificateVerifier for Verifier<'_> {
    fn verify(&self, plan: &IssuancePlan<'_>, certificate_der: &[u8]) -> Result<(), IssueError> {
        verify_server_leaf(
            &self.facts.issuer,
            &self.facts.leaf(),
            plan.tbs_der,
            certificate_der,
            SystemTime::now(),
        )
        .map(|_| ())
        .map_err(|_| IssueError::VerificationFailure)
    }
}

enum Outcome {
    Issued {
        certificate_der: Vec<u8>,
        serial: Vec<u8>,
    },
    AlreadyIssued,
    /// The outcome is ambiguous or refused after the intent: reconciliation.
    Uncertain,
    Conflict,
}

/// Runs issuance on one writer connection. Database refusals before the
/// intent map to the usual statuses.
fn issue(
    db: &mut Client,
    caller: &Caller,
    operation: &str,
    request_sha256: &[u8],
    socket: PathBuf,
) -> Result<Result<Outcome, StatusCode>, postgres::Error> {
    let row = match db.query_one(
        "SELECT request_id::text, request_state, serial, operation_ref, csr_der, subject_cn, \
         dns_names, validity_days, issuer_certificate_der, policy_version FROM \
         begin_application_issuance_lab($1, \
         $2, $3::text::uuid, $4::text::uuid, $5::text::uuid, $6)",
        &[
            &caller.issuer,
            &caller.subject,
            &caller.ca_id,
            &caller.application_id,
            &operation,
            &request_sha256,
        ],
    ) {
        Ok(row) => row,
        Err(error) => return Ok(Err(write_status(&error))),
    };
    let request_id: String = row.get(0);
    match row.get::<_, String>(1).as_str() {
        "SERIAL_RESERVED" => {}
        "SIGNED" => return Ok(Ok(Outcome::AlreadyIssued)),
        // An intent exists: it is never signed twice.
        _ => return Ok(Ok(Outcome::Conflict)),
    }
    let serial: Vec<u8> = row.get(2);
    let operation_ref: String = row.get(3);
    let csr_der: Vec<u8> = row.get(4);
    let subject_cn: String = row.get(5);
    let validity_days: i32 = row.get(7);
    let issuer = match Certificate::from_der(&row.get::<_, Vec<u8>>(8)) {
        Ok(issuer) => issuer,
        Err(_) => return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY)),
    };
    // The stored CSR again: its key is the certificate's subject key.
    let Ok(csr) = verify_pkcs10_p256(&csr_der, &subject_cn) else {
        return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
    };
    // Where the CA publishes its CRLs (migration 0031); the journal records
    // the same URL with the intent, and the signer refuses any other.
    let crl_distribution_point: Option<String> = match db.query_one(
        "SELECT application_crl_distribution_point_lab($1, $2, $3::text::uuid, $4::text::uuid)",
        &[
            &caller.issuer,
            &caller.subject,
            &caller.ca_id,
            &caller.application_id,
        ],
    ) {
        Ok(row) => row.get(0),
        Err(error) => return Ok(Err(write_status(&error))),
    };
    let facts = OwnedFacts {
        crl_distribution_point,
        subject_cn,
        dns_names: row.get(6),
        validity_days: u32::try_from(validity_days).unwrap_or(0),
        serial: serial.clone(),
        subject_public_key: csr.subject_public_key().clone(),
        issuer,
    };
    let Ok(tbs) = build_server_leaf_tbs(&facts.issuer, &facts.leaf(), SystemTime::now()) else {
        return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
    };
    let Ok(tbs_der) = tbs.to_der() else {
        return Ok(Err(StatusCode::UNPROCESSABLE_ENTITY));
    };
    let signer_key_ref = format!("lab-signer:{}", caller.ca_id);
    let policy_version: String = row.get(9);
    let plan = IssuancePlan {
        ca_id: &caller.ca_id,
        request_id: &request_id,
        actor_id: &caller.subject,
        signer_key_ref: &signer_key_ref,
        policy_revision: &policy_version,
        operation_ref: &operation_ref,
        serial_der: &serial,
        tbs_der: &tbs_der,
    };
    let intent_id = Rc::new(RefCell::new(None));
    let mut journal = Journal {
        db,
        caller,
        intent_id: intent_id.clone(),
        facts: &facts,
    };
    let mut signer = SocketSigner { socket, intent_id };
    match issue_once(
        &mut journal,
        &mut signer,
        &Assembler,
        &Verifier { facts: &facts },
        &plan,
    ) {
        Ok(certificate_der) => Ok(Ok(Outcome::Issued {
            certificate_der,
            serial,
        })),
        Err(IssueError::ReplayedOrAmbiguousIntent) => Ok(Ok(Outcome::Conflict)),
        Err(IssueError::JournalFailure) => Ok(Err(StatusCode::CONFLICT)),
        Err(_) => Ok(Ok(Outcome::Uncertain)),
    }
}

/// `POST /v1/cas/{ca_id}/certificate-applications/{id}/issuance`. 201 with
/// the certificate when issued; 200 when it was issued before; 409 when an
/// intent already exists; 502 when the outcome is ambiguous (the request is
/// then RECONCILIATION_REQUIRED and is never re-signed).
pub(crate) async fn issue_application(
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
    let application_id = uuid::Uuid::parse_str(&raw_application)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string();
    let _: IssuanceRequest = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
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
        application_id: application_id.clone(),
    };
    let log_operation = operation.clone();
    let outcome = query_db(writer_url, state.database_slots.clone(), move |db| {
        issue(db, &caller, &operation, &request_sha256, socket)
    })
    .await??;
    let (code, response) = match outcome {
        Outcome::Issued {
            certificate_der,
            serial,
        } => {
            let certificate = Certificate::from_der(&certificate_der)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            (
                StatusCode::CREATED,
                IssuanceResponse {
                    ca_id: ca_id.clone(),
                    application_id: application_id.clone(),
                    status: "ISSUED",
                    certificate_pem: certificate.to_pem(LineEnding::LF).ok(),
                    serial_hex: Some(hex(&serial)),
                    certificate_sha256: Some(hex(&Sha256::digest(&certificate_der))),
                },
            )
        }
        Outcome::AlreadyIssued => (
            StatusCode::OK,
            IssuanceResponse {
                ca_id: ca_id.clone(),
                application_id: application_id.clone(),
                status: "ISSUED",
                certificate_pem: None,
                serial_hex: None,
                certificate_sha256: None,
            },
        ),
        Outcome::Conflict => return Err(StatusCode::CONFLICT),
        Outcome::Uncertain => (
            StatusCode::BAD_GATEWAY,
            IssuanceResponse {
                ca_id: ca_id.clone(),
                application_id: application_id.clone(),
                status: "RECONCILIATION_REQUIRED",
                certificate_pem: None,
                serial_hex: None,
                certificate_sha256: None,
            },
        ),
    };
    write_log(serde_json::json!({
        "event": "certificate_application_issuance", "ca_id": ca_id,
        "application_id": application_id, "status": response.status,
        "operation_id": log_operation,
    }));
    Ok(with_replay_header(
        (code, Json(response)).into_response(),
        code == StatusCode::OK,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_body_is_an_empty_object() {
        assert!(serde_json::from_str::<IssuanceRequest>("{}").is_ok());
        assert!(serde_json::from_str::<IssuanceRequest>(r#"{"tbs":"x"}"#).is_err());
    }
}
