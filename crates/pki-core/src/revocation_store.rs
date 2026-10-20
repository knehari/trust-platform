//! Synchronous PostgreSQL adapter for certificate status changes and the CRL
//! journal, for **laboratory integration** only.
//!
//! Officer identities `(issuer, subject)` and CRL actors must be established by
//! a trusted identity boundary; this module authenticates nobody, owns no keys
//! and signs nothing. Every rule applied here is re-checked by migrations
//! 0014/0015, which remain the authority.

use crate::audit_chain::parse_uuid;
use crate::crl::{check_crl_issuer, CrlEntry, CrlError, CrlReservation};
use crate::crl_orchestrator::{CrlJournal, CrlPlan, CrlReconciliationJournal, ReconciledCrl};
use crate::officer_credential::{
    canonical_officer_key, CredentialChange, CredentialChangeKind, CredentialError,
    StatusChangeClaim,
};
use crate::revocation::{CertificateStatus, OfficerIdentity, RevocationReason, StatusAction};
use crate::revocation_policy::{check_invalidity_date, decide_status_change, StatusChangeError};
use crate::serial::SerialNumber;
use crate::webauthn::{verify_assertion, Assertion, RelyingParty, WebAuthnError};
use postgres::{error::SqlState, types::FromSqlOwned, Client, Error as PgError, NoTls, Row};
use sha2::{Digest, Sha256};
use x509_cert::{der::Encode, Certificate};

#[derive(Debug)]
pub enum RevocationStoreError {
    Database(PgError),
    Denied(StatusChangeError),
    InconsistentResult,
    /// The certificate cannot issue CRLs (see `crl::check_crl_issuer`).
    InvalidIssuer,
    /// The database login is a superuser, may create roles, bypasses row
    /// security or is a member of the owner role: a service must not run
    /// with it (ADR-0006).
    PrivilegedSession,
    /// An officer credential is malformed (key not on P-256, field out of
    /// bounds, CA id not a canonical UUID); nothing was sent (ADR-0007).
    InvalidCredential(CredentialError),
    /// A signed approval failed verification in the Rust core (ADR-0007
    /// step 2); nothing was sent, or stored evidence does not re-verify.
    InvalidAssertion(WebAuthnError),
    /// The credential is unknown, removed or not the acting officer's, the
    /// challenge was already used, or stored evidence is incomplete.
    SignedApprovalRefused,
}

/// A challenge as stored (migration 0029): the claim the officer must sign
/// and who must sign it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedChallenge {
    pub purpose: SignedStep,
    pub claim: StatusChangeClaim,
    pub actor_issuer: String,
    pub actor_subject: String,
    pub consumed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedStep {
    Propose,
    Approve,
}

/// An enrolled credential as stored (migration 0028).
struct StoredCredential {
    issuer: String,
    subject: String,
    public_key_sec1: Vec<u8>,
    sign_count: i64,
    active: bool,
}

fn claim_action(action: &str) -> Result<&'static str, RevocationStoreError> {
    match action {
        "SUSPEND" => Ok("SUSPEND"),
        "RELEASE" => Ok("RELEASE"),
        "REVOKE" => Ok("REVOKE"),
        _ => Err(RevocationStoreError::InconsistentResult),
    }
}

fn hex_uuid(bytes: &[u8; 16]) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let dash = if [4, 6, 8, 10].contains(&i) { "-" } else { "" };
            format!("{dash}{b:02x}")
        })
        .collect()
}

fn uuid_column(row: &Row, idx: usize) -> Result<[u8; 16], RevocationStoreError> {
    let text: String = column(row, idx)?;
    parse_uuid(&text).ok_or(RevocationStoreError::InconsistentResult)
}

fn hash_column(row: &Row, idx: usize) -> Result<[u8; 32], RevocationStoreError> {
    let bytes: Vec<u8> = column(row, idx)?;
    bytes
        .try_into()
        .map_err(|_| RevocationStoreError::InconsistentResult)
}

/// The officer credential content a CA admin proposes or reviews
/// (migration 0028). The key may be in any SEC1 form; it is canonicalised.
pub struct CredentialContent<'a> {
    pub ca_id: &'a str,
    pub credential_id: &'a [u8],
    pub officer: &'a OfficerIdentity<'a>,
    pub person_id: &'a str,
    pub public_key_sec1: &'a [u8],
}

impl CredentialContent<'_> {
    /// The canonical key and the digest the checker approves.
    fn reviewed(
        &self,
        kind: CredentialChangeKind,
    ) -> Result<([u8; 33], [u8; 32]), RevocationStoreError> {
        let key = canonical_officer_key(self.public_key_sec1)
            .map_err(RevocationStoreError::InvalidCredential)?;
        let change = CredentialChange {
            kind,
            ca_id: parse_uuid(self.ca_id).ok_or(RevocationStoreError::InvalidCredential(
                CredentialError::InvalidInput,
            ))?,
            credential_id: self.credential_id,
            officer_issuer: self.officer.issuer,
            officer_subject: self.officer.subject,
            person_id: self.person_id,
            public_key: &key,
        };
        change
            .validate()
            .map_err(RevocationStoreError::InvalidCredential)?;
        Ok((key, change.digest()))
    }
}

/// Officer grant changes under CA-admin dual control (migration 0024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfficerGrantAction {
    Grant,
    Revoke,
}

impl OfficerGrantAction {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Grant => "GRANT_OFFICER",
            Self::Revoke => "REVOKE_OFFICER",
        }
    }
}

/// Digest a CA admin approves for an officer grant change: SHA-256 over the
/// length-prefixed kind, officer issuer and subject, exactly as
/// `ca_admin_content_digest` (migration 0024).
pub fn officer_grant_digest(action: OfficerGrantAction, officer: &OfficerIdentity<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [action.as_sql(), officer.issuer, officer.subject] {
        // Parts are bounded (<= 1024 bytes) by the database, so they fit.
        let len = i32::try_from(part.len()).unwrap_or(i32::MAX);
        hasher.update(len.to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into()
}

impl From<PgError> for RevocationStoreError {
    fn from(value: PgError) -> Self {
        Self::Database(value)
    }
}

/// Column `idx` of `row`; a NULL or mistyped value is an inconsistent
/// database answer, never a panic.
fn column<T: FromSqlOwned>(row: &Row, idx: usize) -> Result<T, RevocationStoreError> {
    row.try_get(idx)
        .map_err(|_| RevocationStoreError::InconsistentResult)
}

/// Result of one `crl_housekeeping` pass for a CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlHousekeepingReport {
    /// RESERVED rows retired as ABANDONED (never signed).
    pub abandoned: i32,
    /// INTENT_RECORDED rows quarantined as RECONCILIATION_REQUIRED.
    pub quarantined: i32,
    /// `crl_due`: no stored CRL, the latest is older than the issue interval,
    /// or an approved change is not reflected by it.
    pub crl_due: bool,
    /// `overdue_status_changes`: changes past their publication deadline.
    pub overdue_changes: i64,
}

impl CrlHousekeepingReport {
    /// True when an operator or the CRL issuer must act.
    pub fn needs_attention(&self) -> bool {
        self.abandoned > 0 || self.quarantined > 0 || self.crl_due || self.overdue_changes > 0
    }
}

pub struct PgRevocationStore {
    client: Client,
}

impl PgRevocationStore {
    /// Only connect to a trusted local/managed PostgreSQL endpoint.
    /// The connection string and TLS policy are the deployment's responsibility.
    /// NoTls is suitable ONLY for CI's loopback test database.
    pub fn connect_lab(conn_str: &str) -> Result<Self, RevocationStoreError> {
        let client = Client::connect(conn_str, NoTls)?;
        Ok(Self { client })
    }

    /// Like `connect_lab`, for a service login: refuses (fail closed) a
    /// session whose login is a superuser, may create roles, bypasses row
    /// security or is a member of `trust_revocation_owner`, since any of
    /// these bypasses the least-privilege model of migration 0023.
    pub fn connect_lab_service(conn_str: &str) -> Result<Self, RevocationStoreError> {
        let mut store = Self::connect_lab(conn_str)?;
        let privileged: bool = column(
            &store.client.query_one(
                "SELECT r.rolsuper OR r.rolcreaterole OR r.rolbypassrls
                        OR pg_has_role(session_user, 'trust_revocation_owner', 'MEMBER')
                 FROM pg_roles r WHERE r.rolname = session_user",
                &[],
            )?,
            0,
        )?;
        if privileged {
            return Err(RevocationStoreError::PrivilegedSession);
        }
        Ok(store)
    }

    /// Proposes `issuer` as this CA's issuer certificate (CA admin, maker).
    /// The certificate is checked as for `register_ca_issuer`; a second CA
    /// admin must approve it with `approve_issuer_registration`.
    pub fn propose_issuer_registration(
        &mut self,
        ca_id: &str,
        issuer: &Certificate,
        maker: &OfficerIdentity<'_>,
    ) -> Result<String, RevocationStoreError> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or(RevocationStoreError::InconsistentResult)?;
        check_crl_issuer(issuer, now_unix).map_err(|_| RevocationStoreError::InvalidIssuer)?;
        let der = issuer
            .to_der()
            .map_err(|_| RevocationStoreError::InvalidIssuer)?;
        let row = self.client.query_one(
            "SELECT propose_ca_admin_change($1::text::uuid, 'REGISTER_ISSUER', $2, NULL, NULL,
                                            $3, $4)::text",
            &[&ca_id, &der, &maker.issuer, &maker.subject],
        )?;
        column(&row, 0)
    }

    /// Approves an issuer registration (CA admin, checker): the database
    /// registers it only if the pending certificate is exactly `issuer`,
    /// the certificate the checker reviewed.
    pub fn approve_issuer_registration(
        &mut self,
        change_id: &str,
        issuer: &Certificate,
        checker: &OfficerIdentity<'_>,
    ) -> Result<(), RevocationStoreError> {
        let der = issuer
            .to_der()
            .map_err(|_| RevocationStoreError::InvalidIssuer)?;
        let digest: [u8; 32] = Sha256::digest(&der).into();
        self.client.query_one(
            "SELECT approve_ca_admin_change($1::text::uuid, $2, $3, $4)",
            &[&change_id, &checker.issuer, &checker.subject, &&digest[..]],
        )?;
        Ok(())
    }

    /// Proposes granting or removing a revocation officer (CA admin, maker).
    pub fn propose_officer_grant(
        &mut self,
        ca_id: &str,
        action: OfficerGrantAction,
        officer: &OfficerIdentity<'_>,
        maker: &OfficerIdentity<'_>,
    ) -> Result<String, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT propose_ca_admin_change($1::text::uuid, $2, NULL, $3, $4, $5, $6)::text",
            &[
                &ca_id,
                &action.as_sql(),
                &officer.issuer,
                &officer.subject,
                &maker.issuer,
                &maker.subject,
            ],
        )?;
        column(&row, 0)
    }

    /// Approves an officer grant change (CA admin, checker) for exactly the
    /// action and officer the checker reviewed.
    pub fn approve_officer_grant(
        &mut self,
        change_id: &str,
        action: OfficerGrantAction,
        officer: &OfficerIdentity<'_>,
        checker: &OfficerIdentity<'_>,
    ) -> Result<(), RevocationStoreError> {
        let digest = officer_grant_digest(action, officer);
        self.client.query_one(
            "SELECT approve_ca_admin_change($1::text::uuid, $2, $3, $4)",
            &[&change_id, &checker.issuer, &checker.subject, &&digest[..]],
        )?;
        Ok(())
    }

    /// Proposes enrolling an officer credential (CA admin, maker). The key
    /// is curve-checked and canonicalised first, so one key in two encodings
    /// is one key to the database.
    pub fn propose_credential_enrollment(
        &mut self,
        content: &CredentialContent<'_>,
        maker: &OfficerIdentity<'_>,
    ) -> Result<String, RevocationStoreError> {
        let (key, _) = content.reviewed(CredentialChangeKind::Enroll)?;
        let row = self.client.query_one(
            "SELECT propose_credential_change($1::text::uuid, 'ENROLL_CREDENTIAL', $2, $3, $4,
                                              $5, $6, $7, $8)::text",
            &[
                &content.ca_id,
                &content.credential_id,
                &content.officer.issuer,
                &content.officer.subject,
                &content.person_id,
                &&key[..],
                &maker.issuer,
                &maker.subject,
            ],
        )?;
        column(&row, 0)
    }

    /// Proposes removing an active officer credential (CA admin, maker).
    pub fn propose_credential_removal(
        &mut self,
        ca_id: &str,
        credential_id: &[u8],
        officer: &OfficerIdentity<'_>,
        maker: &OfficerIdentity<'_>,
    ) -> Result<String, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT propose_credential_change($1::text::uuid, 'REMOVE_CREDENTIAL', $2, $3, $4,
                                              NULL, NULL, $5, $6)::text",
            &[
                &ca_id,
                &credential_id,
                &officer.issuer,
                &officer.subject,
                &maker.issuer,
                &maker.subject,
            ],
        )?;
        column(&row, 0)
    }

    /// Approves a credential change (CA admin, checker) for exactly the
    /// content the checker reviewed; for a removal, the person and key of
    /// the credential being removed.
    pub fn approve_credential_change(
        &mut self,
        change_id: &str,
        kind: CredentialChangeKind,
        reviewed: &CredentialContent<'_>,
        checker: &OfficerIdentity<'_>,
    ) -> Result<(), RevocationStoreError> {
        let (_, digest) = reviewed.reviewed(kind)?;
        self.client.query_one(
            "SELECT approve_credential_change($1::text::uuid, $2, $3, $4)",
            &[&change_id, &checker.issuer, &checker.subject, &&digest[..]],
        )?;
        Ok(())
    }

    /// Asks for a single-use challenge to sign a proposal (ADR-0007 step 2).
    /// Returns the challenge id; `signed_challenge` gives the claim to sign.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_proposal_challenge(
        &mut self,
        ca_id: &str,
        serial: &SerialNumber,
        action: StatusAction,
        reason: Option<RevocationReason>,
        invalidity_at_unix: Option<i64>,
        maker: &OfficerIdentity<'_>,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let code: Option<i16> = reason.map(RevocationReason::code);
        let row = self.client.query_one(
            "SELECT issue_status_change_challenge('PROPOSE', $1::text::uuid, NULL, $2, $3,
                 $4::smallint, to_timestamp($5::bigint::float8), $6, $7, $8)::text",
            &[
                &ca_id,
                &serial.as_der_content(),
                &action.as_sql(),
                &code,
                &invalidity_at_unix,
                &maker.issuer,
                &maker.subject,
                &ttl_seconds,
            ],
        )?;
        column(&row, 0)
    }

    /// Asks for a single-use challenge to sign the approval of `change_id`.
    pub fn issue_approval_challenge(
        &mut self,
        change_id: &str,
        checker: &OfficerIdentity<'_>,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT issue_status_change_challenge('APPROVE', NULL, $1::text::uuid, NULL, NULL,
                 NULL, NULL, $2, $3, $4)::text",
            &[&change_id, &checker.issuer, &checker.subject, &ttl_seconds],
        )?;
        column(&row, 0)
    }

    /// The stored challenge and the claim rebuilt from it: what the officer
    /// signs, and what a submission is verified against.
    pub fn signed_challenge(
        &mut self,
        challenge_id: &str,
    ) -> Result<SignedChallenge, RevocationStoreError> {
        let rows = self.client.query(
            "SELECT purpose, ca_id::text, change_id::text, issuer_certificate_sha256,
                    serial_der_content, action, reason_code, invalidity_us, policy_edition,
                    challenge_sha256, expires_us, actor_issuer, actor_subject, consumed
             FROM status_change_challenge_claim($1::text::uuid)",
            &[&challenge_id],
        )?;
        let row = rows
            .first()
            .ok_or(RevocationStoreError::SignedApprovalRefused)?;
        let purpose = match column::<String>(row, 0)?.as_str() {
            "PROPOSE" => SignedStep::Propose,
            "APPROVE" => SignedStep::Approve,
            _ => return Err(RevocationStoreError::InconsistentResult),
        };
        let reason: Option<i16> = column(row, 6)?;
        let claim = StatusChangeClaim {
            change_id: uuid_column(row, 2)?,
            ca_id: uuid_column(row, 1)?,
            issuer_certificate_sha256: hash_column(row, 3)?,
            serial_der_content: column(row, 4)?,
            action: claim_action(&column::<String>(row, 5)?)?,
            reason: reason
                .map(|r| u8::try_from(r).map_err(|_| RevocationStoreError::InconsistentResult))
                .transpose()?,
            invalidity_date_us: column(row, 7)?,
            policy_edition: column(row, 8)?,
            challenge_sha256: hash_column(row, 9)?,
            expires_at_us: column(row, 10)?,
        };
        claim
            .validate()
            .map_err(|_| RevocationStoreError::InconsistentResult)?;
        Ok(SignedChallenge {
            purpose,
            claim,
            actor_issuer: column(row, 11)?,
            actor_subject: column(row, 12)?,
            consumed: column(row, 13)?,
        })
    }

    fn stored_credential(
        &mut self,
        ca_id: &[u8; 16],
        credential_id: &[u8],
    ) -> Result<StoredCredential, RevocationStoreError> {
        let ca_text = hex_uuid(ca_id);
        let rows = self.client.query(
            "SELECT issuer, subject, public_key_sec1, sign_count, active
             FROM officer_credential_for($1::text::uuid, $2)",
            &[&ca_text, &credential_id],
        )?;
        let row = rows
            .first()
            .ok_or(RevocationStoreError::SignedApprovalRefused)?;
        Ok(StoredCredential {
            issuer: column(row, 0)?,
            subject: column(row, 1)?,
            public_key_sec1: column(row, 2)?,
            sign_count: column(row, 3)?,
            active: column(row, 4)?,
        })
    }

    /// Submits a signed proposal or approval. The Rust core verifies the
    /// WebAuthn assertion against the claim rebuilt from the stored
    /// challenge and the enrolled key before anything is written; the
    /// database re-checks the rest (migration 0029). Returns the change id.
    pub fn submit_signed(
        &mut self,
        challenge_id: &str,
        credential_id: &[u8],
        assertion: &Assertion<'_>,
        rp: &RelyingParty<'_>,
    ) -> Result<String, RevocationStoreError> {
        let challenge = self.signed_challenge(challenge_id)?;
        let credential = self.stored_credential(&challenge.claim.ca_id, credential_id)?;
        if challenge.consumed
            || !credential.active
            || (credential.issuer.as_str(), credential.subject.as_str())
                != (
                    challenge.actor_issuer.as_str(),
                    challenge.actor_subject.as_str(),
                )
        {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        let stored_count = u32::try_from(credential.sign_count)
            .map_err(|_| RevocationStoreError::InconsistentResult)?;
        verify_assertion(
            assertion,
            rp,
            &credential.public_key_sec1,
            &challenge.claim.digest(),
            stored_count,
        )
        .map_err(RevocationStoreError::InvalidAssertion)?;
        let function = match challenge.purpose {
            SignedStep::Propose => "propose_signed_status_change",
            SignedStep::Approve => "approve_signed_status_change",
        };
        self.client.query_one(
            &format!("SELECT {function}($1::text::uuid, $2, $3, $4, $5)::text"),
            &[
                &challenge_id,
                &credential_id,
                &assertion.authenticator_data,
                &assertion.client_data_json,
                &assertion.signature_der,
            ],
        )?;
        Ok(hex_uuid(&challenge.claim.change_id))
    }

    /// Re-verifies the stored evidence of a signed change offline: both
    /// assertions against the enrolled keys and the claims rebuilt from
    /// their challenges, with distinct keys and persons. Exposes an
    /// assertion that reached the database without the Rust core.
    pub fn reverify_signed_change(
        &mut self,
        change_id: &str,
        rp: &RelyingParty<'_>,
    ) -> Result<(), RevocationStoreError> {
        let rows = self.client.query(
            "SELECT role, challenge_id::text, public_key_sec1, person_id, claim_sha256,
                    authenticator_data, client_data_json, signature_der
             FROM status_change_signatures($1::text::uuid)",
            &[&change_id],
        )?;
        if rows.len() != 2 {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        let mut keys = Vec::new();
        let mut persons = Vec::new();
        for row in &rows {
            let challenge = self.signed_challenge(&column::<String>(row, 1)?)?;
            let digest = challenge.claim.digest();
            if hash_column(row, 4)? != digest || hex_uuid(&challenge.claim.change_id) != change_id {
                return Err(RevocationStoreError::SignedApprovalRefused);
            }
            let key: Vec<u8> = column(row, 2)?;
            let authenticator_data: Vec<u8> = column(row, 5)?;
            let client_data_json: Vec<u8> = column(row, 6)?;
            let signature_der: Vec<u8> = column(row, 7)?;
            // The counter was enforced when the evidence was stored; offline
            // only the signature and the bindings are re-checked.
            verify_assertion(
                &Assertion {
                    authenticator_data: &authenticator_data,
                    client_data_json: &client_data_json,
                    signature_der: &signature_der,
                },
                rp,
                &key,
                &digest,
                0,
            )
            .map_err(RevocationStoreError::InvalidAssertion)?;
            keys.push(key);
            persons.push(column::<String>(row, 3)?);
        }
        if keys[0] == keys[1] || persons[0] == persons[1] {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        Ok(())
    }

    /// Registers `issuer` as the certificate this CA signs CRLs with, after
    /// checking it can (`crl::check_crl_issuer`, valid now). Idempotent for
    /// the same certificate; a different one is refused by the database.
    /// Returns its SHA-256, which record_crl_intent requires (0022).
    pub fn register_ca_issuer(
        &mut self,
        ca_id: &str,
        issuer: &Certificate,
        actor: &str,
    ) -> Result<[u8; 32], RevocationStoreError> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or(RevocationStoreError::InconsistentResult)?;
        check_crl_issuer(issuer, now_unix).map_err(|_| RevocationStoreError::InvalidIssuer)?;
        let der = issuer
            .to_der()
            .map_err(|_| RevocationStoreError::InvalidIssuer)?;
        let row = self.client.query_one(
            "SELECT register_ca_issuer($1::text::uuid, $2, $3)",
            &[&ca_id, &der, &actor],
        )?;
        let fingerprint: Vec<u8> = column(&row, 0)?;
        fingerprint
            .try_into()
            .map_err(|_| RevocationStoreError::InconsistentResult)
    }

    pub fn status(
        &mut self,
        ca_id: &str,
        serial: &SerialNumber,
    ) -> Result<CertificateStatus, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT certificate_status($1::text::uuid, $2)",
            &[&ca_id, &serial.as_der_content()],
        )?;
        let value: String = column(&row, 0)?;
        CertificateStatus::from_sql(&value).ok_or(RevocationStoreError::InconsistentResult)
    }

    /// Checks the invalidity date bounds, reads the status and the CA's
    /// suspension policy, applies the pure transition rules, and only then
    /// calls the database function (which re-checks everything). Returns the
    /// change id.
    pub fn propose(
        &mut self,
        ca_id: &str,
        serial: &SerialNumber,
        action: StatusAction,
        reason: Option<RevocationReason>,
        invalidity_at_unix: Option<i64>,
        maker: &OfficerIdentity<'_>,
    ) -> Result<String, RevocationStoreError> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or(RevocationStoreError::InconsistentResult)?;
        // RELEASE carries no reason and no invalidity date (0014 refuses both).
        if action == StatusAction::Release && invalidity_at_unix.is_some() {
            return Err(RevocationStoreError::Denied(
                StatusChangeError::ReasonNotAllowedForAction,
            ));
        }
        check_invalidity_date(invalidity_at_unix, now_unix)
            .map_err(RevocationStoreError::Denied)?;
        let current = self.status(ca_id, serial)?;
        // The suspension policy only matters for SUSPEND.
        let allowed: bool = if action == StatusAction::Suspend {
            column(
                &self.client.query_one(
                    "SELECT COALESCE((SELECT suspension_allowed FROM ca_revocation_policy
                                      WHERE ca_id = $1::text::uuid), false)",
                    &[&ca_id],
                )?,
                0,
            )?
        } else {
            false
        };
        decide_status_change(current, action, reason, allowed)
            .map_err(RevocationStoreError::Denied)?;
        let code: Option<i16> = reason.map(RevocationReason::code);
        let row = self.client.query_one(
            "SELECT propose_certificate_status_change(
                 $1::text::uuid, $2, $3, $4::smallint,
                 to_timestamp($5::bigint::float8), $6, $7)::text",
            &[
                &ca_id,
                &serial.as_der_content(),
                &action.as_sql(),
                &code,
                &invalidity_at_unix,
                &maker.issuer,
                &maker.subject,
            ],
        )?;
        column(&row, 0)
    }

    pub fn approve(
        &mut self,
        change_id: &str,
        checker: &OfficerIdentity<'_>,
        expected_action: StatusAction,
        expected_reason: Option<RevocationReason>,
    ) -> Result<(), RevocationStoreError> {
        let code: Option<i16> = expected_reason.map(RevocationReason::code);
        self.client.query_one(
            "SELECT approve_certificate_status_change(
                 $1::text::uuid, $2, $3, $4, $5::smallint)",
            &[
                &change_id,
                &checker.issuer,
                &checker.subject,
                &expected_action.as_sql(),
                &code,
            ],
        )?;
        Ok(())
    }

    pub fn reject(
        &mut self,
        change_id: &str,
        checker: &OfficerIdentity<'_>,
    ) -> Result<(), RevocationStoreError> {
        self.client.query_one(
            "SELECT reject_certificate_status_change($1::text::uuid, $2, $3)",
            &[&change_id, &checker.issuer, &checker.subject],
        )?;
        Ok(())
    }

    pub fn withdraw(
        &mut self,
        change_id: &str,
        maker: &OfficerIdentity<'_>,
    ) -> Result<(), RevocationStoreError> {
        self.client.query_one(
            "SELECT withdraw_certificate_status_change($1::text::uuid, $2, $3)",
            &[&change_id, &maker.issuer, &maker.subject],
        )?;
        Ok(())
    }

    /// `reserve_crl` requires READ COMMITTED (the session default) and is
    /// deliberately NOT wrapped in a stricter transaction.
    pub fn reserve_crl(
        &mut self,
        ca_id: &str,
        actor: &str,
        operation_ref: &str,
    ) -> Result<CrlReservation, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT crl_number,
                    floor(extract(epoch FROM this_update))::bigint,
                    floor(extract(epoch FROM next_update))::bigint,
                    floor(extract(epoch FROM expired_certs_on_crl_since))::bigint
             FROM reserve_crl($1::text::uuid, $2, $3)",
            &[&ca_id, &actor, &operation_ref],
        )?;
        let number: i64 = column(&row, 0)?;
        self.reservation_from_snapshot(
            ca_id,
            number,
            column(&row, 1)?,
            column(&row, 2)?,
            column(&row, 3)?,
        )
    }

    /// Rebuilds the sealed reservation of an existing CRL number from its
    /// publication row and frozen snapshot, e.g. to reconcile a quarantined
    /// CRL with `crl_orchestrator::reconcile_crl`.
    pub fn load_reservation(
        &mut self,
        ca_id: &str,
        crl_number: u64,
    ) -> Result<CrlReservation, RevocationStoreError> {
        let number =
            i64::try_from(crl_number).map_err(|_| RevocationStoreError::InconsistentResult)?;
        let row = self.client.query_one(
            "SELECT floor(extract(epoch FROM this_update))::bigint,
                    floor(extract(epoch FROM next_update))::bigint,
                    floor(extract(epoch FROM expired_certs_on_crl_since))::bigint
             FROM crl_publication WHERE ca_id = $1::text::uuid AND crl_number = $2",
            &[&ca_id, &number],
        )?;
        self.reservation_from_snapshot(
            ca_id,
            number,
            column(&row, 0)?,
            column(&row, 1)?,
            column(&row, 2)?,
        )
    }

    fn reservation_from_snapshot(
        &mut self,
        ca_id: &str,
        number: i64,
        this_update_unix: i64,
        next_update_unix: i64,
        expired_certs_on_crl_since_unix: Option<i64>,
    ) -> Result<CrlReservation, RevocationStoreError> {
        let rows = self.client.query(
            "SELECT serial_der_content,
                    floor(extract(epoch FROM revoked_at))::bigint,
                    reason_code,
                    floor(extract(epoch FROM invalidity_at))::bigint
             FROM crl_snapshot_entries($1::text::uuid, $2::bigint)",
            &[&ca_id, &number],
        )?;
        let mut entries = Vec::with_capacity(rows.len());
        for r in rows {
            let serial_bytes: Vec<u8> = column(&r, 0)?;
            let reason_code: i16 = column(&r, 2)?;
            entries.push(CrlEntry {
                serial: SerialNumber::from_positive_der_content(&serial_bytes)
                    .map_err(|_| RevocationStoreError::InconsistentResult)?,
                revoked_at_unix: column(&r, 1)?,
                reason: RevocationReason::from_code(reason_code)
                    .map_err(|_| RevocationStoreError::InconsistentResult)?,
                invalidity_at_unix: column(&r, 3)?,
            });
        }
        // The sealed reservation is the only thing the CA core can sign; its
        // entries digest must equal the snapshot's or record_crl_intent refuses.
        CrlReservation::new(
            ca_id,
            u64::try_from(number).map_err(|_| RevocationStoreError::InconsistentResult)?,
            this_update_unix,
            next_update_unix,
            entries,
            expired_certs_on_crl_since_unix,
        )
        .map_err(|_| RevocationStoreError::InconsistentResult)
    }

    /// Retires RESERVED rows older than the threshold (no intent, so never
    /// signed); `record_crl_intent` then refuses them. Returns the count.
    pub fn abandon_stale_crl_reservations(
        &mut self,
        ca_id: &str,
        older_than_seconds: i64,
    ) -> Result<i32, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT abandon_stale_crl_reservations(
                 $1::text::uuid, make_interval(secs => $2::bigint::float8))",
            &[&ca_id, &older_than_seconds],
        )?;
        column(&row, 0)
    }

    /// One scheduled housekeeping pass (ADR-0006 part C): retire stale
    /// reservations, quarantine stale intents, then report whether a CRL is
    /// due and how many changes are past their publication deadline.
    pub fn crl_housekeeping(
        &mut self,
        ca_id: &str,
        reserved_older_than_seconds: i64,
        intent_older_than_seconds: i64,
    ) -> Result<CrlHousekeepingReport, RevocationStoreError> {
        let abandoned = self.abandon_stale_crl_reservations(ca_id, reserved_older_than_seconds)?;
        let quarantined = self.quarantine_stale_crl_intents(ca_id, intent_older_than_seconds)?;
        let row = self.client.query_one(
            "SELECT crl_due($1::text::uuid),
                    (SELECT count(*) FROM overdue_status_changes($1::text::uuid))",
            &[&ca_id],
        )?;
        Ok(CrlHousekeepingReport {
            abandoned,
            quarantined,
            crl_due: column(&row, 0)?,
            overdue_changes: column(&row, 1)?,
        })
    }

    /// Schema changes (DDL, object grants) recorded since the last reviewed
    /// migration acknowledged them (migration 0026, ADR-0006 condition 3).
    /// Database-wide, not per CA; anything above zero needs an operator.
    pub fn unreviewed_schema_changes(&mut self) -> Result<i64, RevocationStoreError> {
        let row = self
            .client
            .query_one("SELECT unreviewed_schema_changes()", &[])?;
        column(&row, 0)
    }

    pub fn quarantine_stale_crl_intents(
        &mut self,
        ca_id: &str,
        older_than_seconds: i64,
    ) -> Result<i32, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT quarantine_stale_crl_intents(
                 $1::text::uuid, make_interval(secs => $2::bigint::float8))",
            &[&ca_id, &older_than_seconds],
        )?;
        column(&row, 0)
    }
}

impl CrlReconciliationJournal for PgRevocationStore {
    fn store_reconciled(
        &mut self,
        reservation: &CrlReservation,
        operation_ref: &str,
        actor: &str,
        crl: &ReconciledCrl<'_>,
    ) -> Result<(), CrlError> {
        let number =
            i64::try_from(reservation.crl_number()).map_err(|_| CrlError::PersistenceFailure)?;
        match self.client.query_one(
            "SELECT store_reconciled_crl($1::text::uuid, $2::bigint, $3, $4, $5, $6, $7, $8)",
            &[
                &reservation.ca_id(),
                &number,
                &operation_ref,
                &&crl.tbs_sha256[..],
                &&crl.crl_sha256[..],
                &crl.crl_der,
                &actor,
                &&crl.issuer_sha256[..],
            ],
        ) {
            Ok(_) => Ok(()),
            // Not the CA's registered issuer certificate (0022).
            Err(e) if e.code() == Some(&SqlState::UNDEFINED_OBJECT) => {
                Err(CrlError::IssuerMismatch)
            }
            // Not quarantined after an intent, other operation or TBS hash.
            Err(e) if e.code() == Some(&SqlState::CHECK_VIOLATION) => {
                Err(CrlError::ReplayedOrAmbiguousIntent)
            }
            Err(_) => Err(CrlError::PersistenceFailure),
        }
    }
}

impl CrlJournal for PgRevocationStore {
    /// Binds the intent to what will be signed: the entries digest is computed
    /// here from the reservation (not taken from the database), and the
    /// database refuses it unless entries, number and times match the
    /// reserved snapshot.
    fn record_intent(&mut self, plan: &CrlPlan<'_>, tbs_sha256: &[u8; 32]) -> Result<(), CrlError> {
        let reservation = plan.reservation;
        let number =
            i64::try_from(reservation.crl_number()).map_err(|_| CrlError::JournalFailure)?;
        let entries_sha256 = reservation.entries_sha256();
        // Binds the intent to the CA's registered issuer certificate (0022).
        let issuer_der = plan.issuer.to_der().map_err(|_| CrlError::IssuerMismatch)?;
        let issuer_sha256: [u8; 32] = Sha256::digest(&issuer_der).into();
        match self.client.query_one(
            "SELECT record_crl_intent($1::text::uuid, $2::bigint, $3, $4, $5,
                                      $6::bigint, $7::bigint, $8::bigint, $9)",
            &[
                &reservation.ca_id(),
                &number,
                &plan.operation_ref,
                &&tbs_sha256[..],
                &&entries_sha256[..],
                &reservation.this_update_unix(),
                &reservation.next_update_unix(),
                &reservation.expired_certs_on_crl_since_unix(),
                &&issuer_sha256[..],
            ],
        ) {
            Ok(_) => Ok(()),
            // Not the CA's registered issuer certificate (0022).
            Err(e) if e.code() == Some(&SqlState::UNDEFINED_OBJECT) => {
                Err(CrlError::IssuerMismatch)
            }
            // Not RESERVED any more, another operation, or entries / number /
            // times that differ from the reservation: replayed or ambiguous.
            Err(e) if e.code() == Some(&SqlState::CHECK_VIOLATION) => {
                Err(CrlError::ReplayedOrAmbiguousIntent)
            }
            // Certain refusal (migration 0021): nothing signed, reserve again.
            Err(e) if e.code() == Some(&SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE) => {
                Err(CrlError::ReserveAgain)
            }
            Err(_) => Err(CrlError::JournalFailure),
        }
    }

    fn mark_uncertain(&mut self, plan: &CrlPlan<'_>) -> Result<(), CrlError> {
        let number =
            i64::try_from(plan.reservation.crl_number()).map_err(|_| CrlError::JournalFailure)?;
        self.client
            .query_one(
                "SELECT mark_crl_uncertain($1::text::uuid, $2::bigint, $3)",
                &[&plan.reservation.ca_id(), &number, &plan.operation_ref],
            )
            .map(|_| ())
            .map_err(|_| CrlError::JournalFailure)
    }

    fn persist_verified(
        &mut self,
        plan: &CrlPlan<'_>,
        tbs_sha256: &[u8; 32],
        crl_sha256: &[u8; 32],
        crl_der: &[u8],
    ) -> Result<(), CrlError> {
        let number = i64::try_from(plan.reservation.crl_number())
            .map_err(|_| CrlError::PersistenceFailure)?;
        self.client
            .query_one(
                "SELECT store_verified_crl($1::text::uuid, $2::bigint, $3, $4, $5, $6)",
                &[
                    &plan.reservation.ca_id(),
                    &number,
                    &plan.operation_ref,
                    &&tbs_sha256[..],
                    &&crl_sha256[..],
                    &crl_der,
                ],
            )
            .map(|_| ())
            .map_err(|_| CrlError::PersistenceFailure)
    }
}
