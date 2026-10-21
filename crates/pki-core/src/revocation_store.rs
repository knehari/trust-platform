//! Synchronous PostgreSQL adapter for certificate status changes and the CRL
//! journal, for **laboratory integration** only.
//!
//! Officer identities `(issuer, subject)` and CRL actors must be established by
//! a trusted identity boundary; this module authenticates nobody, owns no keys
//! and signs nothing. Every rule applied here is re-checked by migrations
//! 0014/0015, which remain the authority.

use crate::audit_chain::parse_uuid;
use crate::clock::{
    system_clock_us, this_update_plausible, ClockReading, ClockSource, DEFAULT_MAX_CLOCK_SKEW_US,
};
use crate::crl::{check_crl_issuer, check_pruned_entry, CrlEntry, CrlError, CrlReservation};
use crate::crl_orchestrator::{CrlJournal, CrlPlan, CrlReconciliationJournal, ReconciledCrl};
use crate::officer_credential::{
    canonical_officer_key, CaAdminClaim, CredentialChange, CredentialChangeKind, CredentialError,
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
    /// The database clock disagrees with the Rust core's clock beyond the
    /// configured bound (ADR-0006 condition 6). Nothing was signed; a CRL
    /// reservation made meanwhile stays RESERVED and housekeeping retires it.
    ClockSkew,
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
    /// A single-officer precautionary hold (migration 0036).
    Precaution,
}

/// The two families of CA-administration changes (0024, 0028).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminFamily {
    /// Issuer registration and officer grants (`ca_admin_change`).
    CaAdmin,
    /// Officer credential enrolment and removal (`officer_credential_change`).
    Credential,
}

impl AdminFamily {
    fn as_sql(self) -> &'static str {
        match self {
            Self::CaAdmin => "CA_ADMIN",
            Self::Credential => "CREDENTIAL",
        }
    }
}

/// A CA-administration change as the maker reviews and signs it.
pub enum AdminChange<'a> {
    RegisterIssuer(&'a Certificate),
    Officer(OfficerGrantAction, &'a OfficerIdentity<'a>),
    /// For a removal, the person and key of the credential being removed.
    Credential(CredentialChangeKind, &'a CredentialContent<'a>),
}

/// What `propose_signed_admin_change` takes besides the assertion.
struct AdminContentParams {
    certificate_der: Option<Vec<u8>>,
    credential_id: Option<Vec<u8>>,
    officer_issuer: Option<String>,
    officer_subject: Option<String>,
    person_id: Option<String>,
    public_key_sec1: Option<Vec<u8>>,
}

impl AdminChange<'_> {
    pub fn family(&self) -> AdminFamily {
        match self {
            Self::RegisterIssuer(_) | Self::Officer(..) => AdminFamily::CaAdmin,
            Self::Credential(..) => AdminFamily::Credential,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::RegisterIssuer(_) => "REGISTER_ISSUER",
            Self::Officer(action, _) => action.as_sql(),
            Self::Credential(kind, _) => kind.as_sql(),
        }
    }

    /// The content digest the maker and the checker sign (the 0024 / 0028
    /// digests); an issuer certificate is checked as for registration.
    fn reviewed(&self) -> Result<([u8; 32], AdminContentParams), RevocationStoreError> {
        let none = AdminContentParams {
            certificate_der: None,
            credential_id: None,
            officer_issuer: None,
            officer_subject: None,
            person_id: None,
            public_key_sec1: None,
        };
        match self {
            Self::RegisterIssuer(issuer) => {
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .and_then(|d| i64::try_from(d.as_secs()).ok())
                    .ok_or(RevocationStoreError::InconsistentResult)?;
                check_crl_issuer(issuer, now_unix)
                    .map_err(|_| RevocationStoreError::InvalidIssuer)?;
                let der = issuer
                    .to_der()
                    .map_err(|_| RevocationStoreError::InvalidIssuer)?;
                Ok((
                    Sha256::digest(&der).into(),
                    AdminContentParams {
                        certificate_der: Some(der),
                        ..none
                    },
                ))
            }
            Self::Officer(action, officer) => Ok((
                officer_grant_digest(*action, officer),
                AdminContentParams {
                    officer_issuer: Some(officer.issuer.to_owned()),
                    officer_subject: Some(officer.subject.to_owned()),
                    ..none
                },
            )),
            Self::Credential(kind, content) => {
                let (key, digest) = content.reviewed(*kind)?;
                // A removal names the credential; the database takes person
                // and key from the stored credential (and signs them here).
                let enroll = *kind == CredentialChangeKind::Enroll;
                Ok((
                    digest,
                    AdminContentParams {
                        credential_id: Some(content.credential_id.to_vec()),
                        officer_issuer: Some(content.officer.issuer.to_owned()),
                        officer_subject: Some(content.officer.subject.to_owned()),
                        person_id: enroll.then(|| content.person_id.to_owned()),
                        public_key_sec1: enroll.then(|| key.to_vec()),
                        ..none
                    },
                ))
            }
        }
    }
}

/// A CA-admin challenge as stored (migration 0037).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminChallenge {
    pub purpose: SignedStep,
    pub claim: CaAdminClaim,
    pub actor_issuer: String,
    pub actor_subject: String,
    pub consumed: bool,
}

/// A precautionary hold still awaiting its dual-controlled revocation or
/// release (migration 0036).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecautionaryHold {
    pub change_id: String,
    pub serial_der_content: Vec<u8>,
    pub maker_issuer: String,
    pub maker_subject: String,
    pub held_at_unix: i64,
    pub confirm_by_unix: i64,
    pub overdue: bool,
}

/// A proposed status change waiting for a checker (migration 0034).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStatusChange {
    pub change_id: String,
    pub serial_der_content: Vec<u8>,
    pub action: String,
    pub reason_code: Option<i16>,
    pub invalidity_at_unix: Option<i64>,
    pub maker_issuer: String,
    pub maker_subject: String,
    pub proposed_at_unix: i64,
    pub maker_signed: bool,
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
        "PRECAUTIONARY_SUSPEND" => Ok("PRECAUTIONARY_SUSPEND"),
        _ => Err(RevocationStoreError::InconsistentResult),
    }
}

fn admin_kind(kind: &str) -> Result<&'static str, RevocationStoreError> {
    match kind {
        "REGISTER_ISSUER" => Ok("REGISTER_ISSUER"),
        "GRANT_OFFICER" => Ok("GRANT_OFFICER"),
        "REVOKE_OFFICER" => Ok("REVOKE_OFFICER"),
        "ENROLL_CREDENTIAL" => Ok("ENROLL_CREDENTIAL"),
        "REMOVE_CREDENTIAL" => Ok("REMOVE_CREDENTIAL"),
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
    /// Precautionary holds past their confirmation deadline (0036) without
    /// a dual-controlled revocation or release.
    pub overdue_precautionary_holds: i64,
    /// Database clock against the Rust core's clock (ADR-0006 condition 6).
    pub clock: ClockReading,
    pub clock_within_bound: bool,
}

impl CrlHousekeepingReport {
    /// True when an operator or the CRL issuer must act.
    pub fn needs_attention(&self) -> bool {
        self.abandoned > 0
            || self.quarantined > 0
            || self.crl_due
            || self.overdue_changes > 0
            || self.overdue_precautionary_holds > 0
            || !self.clock_within_bound
    }
}

pub struct PgRevocationStore {
    client: Client,
    clock: ClockSource,
    max_clock_skew_us: i64,
}

impl PgRevocationStore {
    /// Only connect to a trusted local/managed PostgreSQL endpoint.
    /// The connection string and TLS policy are the deployment's responsibility.
    /// NoTls is suitable ONLY for CI's loopback test database.
    pub fn connect_lab(conn_str: &str) -> Result<Self, RevocationStoreError> {
        let client = Client::connect(conn_str, NoTls)?;
        Ok(Self {
            client,
            clock: system_clock_us,
            max_clock_skew_us: DEFAULT_MAX_CLOCK_SKEW_US,
        })
    }

    /// Like `connect_lab`, for a service login: refuses (fail closed) a
    /// session whose login is a superuser, may create roles, bypasses row
    /// security or is a member of `trust_revocation_owner`, since any of
    /// these bypasses the least-privilege model of migration 0023.
    pub fn connect_lab_service(conn_str: &str) -> Result<Self, RevocationStoreError> {
        Self::from_service_client(Client::connect(conn_str, NoTls)?)
    }

    /// A service session on a client the caller connected under its own
    /// TLS policy (e.g. verify-full); refuses a privileged login exactly like
    /// `connect_lab_service`.
    pub fn from_service_client(client: Client) -> Result<Self, RevocationStoreError> {
        let mut store = Self {
            client,
            clock: system_clock_us,
            max_clock_skew_us: DEFAULT_MAX_CLOCK_SKEW_US,
        };
        let privileged: bool = column(
            &store.client.query_one(
                "SELECT r.rolsuper OR r.rolcreaterole OR r.rolbypassrls
                        OR CASE WHEN EXISTS (SELECT 1 FROM pg_roles
                                             WHERE rolname = 'trust_revocation_owner')
                                THEN pg_has_role(session_user, 'trust_revocation_owner', 'MEMBER')
                                ELSE false END
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

    /// Asks for a single-use challenge to put `serial` on hold as a
    /// precaution, signed by one officer (ADR-0007 §6, migration 0036). The
    /// database refuses unless the CA allows suspension under a CPS
    /// reference, sets a confirmation deadline and the certificate is valid.
    pub fn issue_precaution_challenge(
        &mut self,
        ca_id: &str,
        serial: &SerialNumber,
        officer: &OfficerIdentity<'_>,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT issue_precautionary_hold_challenge($1::text::uuid, $2, $3, $4, $5)::text",
            &[
                &ca_id,
                &serial.as_der_content(),
                &officer.issuer,
                &officer.subject,
                &ttl_seconds,
            ],
        )?;
        column(&row, 0)
    }

    /// The CA's precautionary holds not yet followed by a dual-controlled
    /// revocation or release, oldest first, with whether the deadline passed.
    pub fn precautionary_holds(
        &mut self,
        ca_id: &str,
    ) -> Result<Vec<PrecautionaryHold>, RevocationStoreError> {
        let rows = self.client.query(
            "SELECT change_id::text, serial_der_content, maker_issuer, maker_subject,
                    extract(epoch FROM held_at)::bigint, extract(epoch FROM confirm_by)::bigint,
                    overdue
             FROM precautionary_holds($1::text::uuid)",
            &[&ca_id],
        )?;
        rows.iter()
            .map(|row| {
                Ok(PrecautionaryHold {
                    change_id: column(row, 0)?,
                    serial_der_content: column(row, 1)?,
                    maker_issuer: column(row, 2)?,
                    maker_subject: column(row, 3)?,
                    held_at_unix: column(row, 4)?,
                    confirm_by_unix: column(row, 5)?,
                    overdue: column(row, 6)?,
                })
            })
            .collect()
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
            "PRECAUTION" => SignedStep::Precaution,
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
            SignedStep::Precaution => "apply_precautionary_hold",
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
    /// their challenges, with distinct keys and persons (or the single
    /// signature of a precautionary hold, 0036). Exposes an
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
        // A maker and a checker signature (ordinary change), or a single
        // precautionary-hold signature (0036); nothing else is evidence.
        if !(1..=2).contains(&rows.len()) {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        let mut keys = Vec::new();
        let mut persons = Vec::new();
        let mut steps = Vec::new();
        for row in &rows {
            let challenge = self.signed_challenge(&column::<String>(row, 1)?)?;
            steps.push(challenge.purpose);
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
        let complete = match steps.as_slice() {
            [SignedStep::Precaution] => true,
            [SignedStep::Propose, SignedStep::Approve] => {
                keys[0] != keys[1] && persons[0] != persons[1]
            }
            _ => false,
        };
        complete
            .then_some(())
            .ok_or(RevocationStoreError::SignedApprovalRefused)
    }

    /// DBA bootstrap of a CA admin's WebAuthn key (migration 0037), like
    /// `ca_admin_grant`: needs a superuser login; no service may call it.
    /// The key is curve-checked and canonicalised first.
    pub fn enroll_admin_credential(
        &mut self,
        ca_id: &str,
        credential_id: &[u8],
        admin: &OfficerIdentity<'_>,
        person_id: &str,
        public_key_sec1: &[u8],
    ) -> Result<(), RevocationStoreError> {
        let key = canonical_officer_key(public_key_sec1)
            .map_err(RevocationStoreError::InvalidCredential)?;
        self.client.execute(
            "SELECT enroll_ca_admin_credential($1::text::uuid, $2, $3, $4, $5, $6)",
            &[
                &ca_id,
                &credential_id,
                &admin.issuer,
                &admin.subject,
                &person_id,
                &&key[..],
            ],
        )?;
        Ok(())
    }

    /// Asks for a single-use challenge to sign a CA-admin proposal
    /// (ADR-0007, `trust-platform/ca-admin/v1`, migration 0037).
    pub fn issue_admin_proposal_challenge(
        &mut self,
        ca_id: &str,
        change: &AdminChange<'_>,
        maker: &OfficerIdentity<'_>,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let (digest, _) = change.reviewed()?;
        let row = self.client.query_one(
            "SELECT issue_ca_admin_challenge('PROPOSE', $1::text::uuid, $2, $3, $4, NULL,
                                             $5, $6, $7)::text",
            &[
                &ca_id,
                &change.family().as_sql(),
                &change.kind(),
                &&digest[..],
                &maker.issuer,
                &maker.subject,
                &ttl_seconds,
            ],
        )?;
        column(&row, 0)
    }

    /// Asks for a single-use challenge to sign the approval of a CA-admin
    /// change; kind and content come from the pending change.
    pub fn issue_admin_approval_challenge(
        &mut self,
        family: AdminFamily,
        change_id: &str,
        checker: &OfficerIdentity<'_>,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT issue_ca_admin_challenge('APPROVE', NULL, $1, NULL, NULL, $2::text::uuid,
                                             $3, $4, $5)::text",
            &[
                &family.as_sql(),
                &change_id,
                &checker.issuer,
                &checker.subject,
                &ttl_seconds,
            ],
        )?;
        column(&row, 0)
    }

    /// The stored CA-admin challenge and the claim rebuilt from it.
    pub fn admin_challenge(
        &mut self,
        challenge_id: &str,
    ) -> Result<AdminChallenge, RevocationStoreError> {
        let rows = self.client.query(
            "SELECT purpose, ca_id::text, family, kind, change_id::text,
                    issuer_certificate_sha256, content_sha256, policy_edition,
                    challenge_sha256, expires_us, actor_issuer, actor_subject, consumed
             FROM ca_admin_challenge_claim($1::text::uuid)",
            &[&challenge_id],
        )?;
        let row = rows
            .first()
            .ok_or(RevocationStoreError::SignedApprovalRefused)?;
        let (purpose, step) = match column::<String>(row, 0)?.as_str() {
            "PROPOSE" => (SignedStep::Propose, "PROPOSE"),
            "APPROVE" => (SignedStep::Approve, "APPROVE"),
            _ => return Err(RevocationStoreError::InconsistentResult),
        };
        let family = match column::<String>(row, 2)?.as_str() {
            "CA_ADMIN" => "CA_ADMIN",
            "CREDENTIAL" => "CREDENTIAL",
            _ => return Err(RevocationStoreError::InconsistentResult),
        };
        let change_id = column::<Option<String>>(row, 4)?
            .map(|text| parse_uuid(&text).ok_or(RevocationStoreError::InconsistentResult))
            .transpose()?;
        let issuer = column::<Option<Vec<u8>>>(row, 5)?
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes).map_err(|_| RevocationStoreError::InconsistentResult)
            })
            .transpose()?;
        let claim = CaAdminClaim {
            step,
            ca_id: uuid_column(row, 1)?,
            issuer_certificate_sha256: issuer,
            family,
            kind: admin_kind(&column::<String>(row, 3)?)?,
            change_id,
            content_sha256: hash_column(row, 6)?,
            policy_edition: column(row, 7)?,
            challenge_sha256: hash_column(row, 8)?,
            expires_at_us: column(row, 9)?,
        };
        claim
            .validate()
            .map_err(|_| RevocationStoreError::InconsistentResult)?;
        Ok(AdminChallenge {
            purpose,
            claim,
            actor_issuer: column(row, 10)?,
            actor_subject: column(row, 11)?,
            consumed: column(row, 12)?,
        })
    }

    /// Submits a signed CA-admin proposal (with the `change` the maker
    /// reviewed, which must be the signed one) or approval (`change` None).
    /// The WebAuthn assertion is verified against the claim rebuilt from the
    /// stored challenge and the enrolled admin key before anything is
    /// written; the database re-checks the rest (migration 0037). Returns
    /// the change id.
    pub fn submit_signed_admin(
        &mut self,
        challenge_id: &str,
        credential_id: &[u8],
        assertion: &Assertion<'_>,
        rp: &RelyingParty<'_>,
        change: Option<&AdminChange<'_>>,
    ) -> Result<String, RevocationStoreError> {
        let challenge = self.admin_challenge(challenge_id)?;
        let ca_text = hex_uuid(&challenge.claim.ca_id);
        let rows = self.client.query(
            "SELECT issuer, subject, public_key_sec1, sign_count, active
             FROM ca_admin_credential_for($1::text::uuid, $2)",
            &[&ca_text, &credential_id],
        )?;
        let row = rows
            .first()
            .ok_or(RevocationStoreError::SignedApprovalRefused)?;
        let credential = StoredCredential {
            issuer: column(row, 0)?,
            subject: column(row, 1)?,
            public_key_sec1: column(row, 2)?,
            sign_count: column(row, 3)?,
            active: column(row, 4)?,
        };
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
        // A proposal must carry exactly the content that was signed.
        let params = match (challenge.purpose, change) {
            (SignedStep::Propose, Some(change)) => {
                let (digest, params) = change.reviewed()?;
                if change.family().as_sql() != challenge.claim.family
                    || change.kind() != challenge.claim.kind
                    || digest != challenge.claim.content_sha256
                {
                    return Err(RevocationStoreError::SignedApprovalRefused);
                }
                Some(params)
            }
            (SignedStep::Approve, None) => None,
            _ => return Err(RevocationStoreError::SignedApprovalRefused),
        };
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
        match params {
            Some(p) => {
                let row = self.client.query_one(
                    "SELECT propose_signed_admin_change($1::text::uuid, $2, $3, $4, $5,
                                                        $6, $7, $8, $9, $10, $11)::text",
                    &[
                        &challenge_id,
                        &credential_id,
                        &assertion.authenticator_data,
                        &assertion.client_data_json,
                        &assertion.signature_der,
                        &p.certificate_der,
                        &p.credential_id,
                        &p.officer_issuer,
                        &p.officer_subject,
                        &p.person_id,
                        &p.public_key_sec1,
                    ],
                )?;
                column(&row, 0)
            }
            None => {
                self.client.query_one(
                    "SELECT approve_signed_admin_change($1::text::uuid, $2, $3, $4, $5)",
                    &[
                        &challenge_id,
                        &credential_id,
                        &assertion.authenticator_data,
                        &assertion.client_data_json,
                        &assertion.signature_der,
                    ],
                )?;
                challenge
                    .claim
                    .change_id
                    .as_ref()
                    .map(hex_uuid)
                    .ok_or(RevocationStoreError::InconsistentResult)
            }
        }
    }

    /// Re-verifies a signed CA-admin change offline: a proposal and an
    /// approval signature, each against the enrolled admin key and the
    /// claim rebuilt from its challenge; both claims name the change's CA,
    /// kind and content, the approval names the change; keys and persons
    /// differ.
    pub fn reverify_admin_change(
        &mut self,
        family: AdminFamily,
        change_id: &str,
        rp: &RelyingParty<'_>,
    ) -> Result<(), RevocationStoreError> {
        let rows = self.client.query(
            "SELECT role, challenge_id::text, public_key_sec1, person_id, claim_sha256,
                    authenticator_data, client_data_json, signature_der, change_ca::text,
                    change_kind, change_content_sha256
             FROM ca_admin_signatures($1, $2::text::uuid)",
            &[&family.as_sql(), &change_id],
        )?;
        if rows.len() != 2 {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        let mut keys = Vec::new();
        let mut persons = Vec::new();
        let mut steps = Vec::new();
        for row in &rows {
            let challenge = self.admin_challenge(&column::<String>(row, 1)?)?;
            let claim = &challenge.claim;
            let digest = claim.digest();
            let names_change = match challenge.purpose {
                SignedStep::Approve => {
                    claim.change_id.as_ref().map(hex_uuid).as_deref() == Some(change_id)
                }
                _ => claim.change_id.is_none(),
            };
            if hash_column(row, 4)? != digest
                || !names_change
                || claim.family != family.as_sql()
                || claim.ca_id != uuid_column(row, 8)?
                || claim.kind != column::<String>(row, 9)?
                || claim.content_sha256 != hash_column(row, 10)?
            {
                return Err(RevocationStoreError::SignedApprovalRefused);
            }
            let key: Vec<u8> = column(row, 2)?;
            let authenticator_data: Vec<u8> = column(row, 5)?;
            let client_data_json: Vec<u8> = column(row, 6)?;
            let signature_der: Vec<u8> = column(row, 7)?;
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
            steps.push(challenge.purpose);
            keys.push(key);
            persons.push(column::<String>(row, 3)?);
        }
        let complete = steps == [SignedStep::Propose, SignedStep::Approve]
            && keys[0] != keys[1]
            && persons[0] != persons[1];
        complete
            .then_some(())
            .ok_or(RevocationStoreError::SignedApprovalRefused)
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

    /// The CA's proposed changes, oldest first (at most 500; migration 0034).
    pub fn pending_status_changes(
        &mut self,
        ca_id: &str,
    ) -> Result<Vec<PendingStatusChange>, RevocationStoreError> {
        self.client
            .query(
                "SELECT change_id::text, serial_der_content, action, reason_code,
                        floor(extract(epoch FROM invalidity_at))::bigint, maker_issuer,
                        maker_subject, floor(extract(epoch FROM proposed_at))::bigint,
                        maker_signed
                 FROM pending_status_changes($1::text::uuid)",
                &[&ca_id],
            )?
            .iter()
            .map(|row| {
                Ok(PendingStatusChange {
                    change_id: column(row, 0)?,
                    serial_der_content: column(row, 1)?,
                    action: column(row, 2)?,
                    reason_code: column(row, 3)?,
                    invalidity_at_unix: column(row, 4)?,
                    maker_issuer: column(row, 5)?,
                    maker_subject: column(row, 6)?,
                    proposed_at_unix: column(row, 7)?,
                    maker_signed: column(row, 8)?,
                })
            })
            .collect()
    }

    /// The CA a change belongs to, if it exists (migration 0034).
    pub fn status_change_ca(
        &mut self,
        change_id: &str,
    ) -> Result<Option<String>, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT status_change_ca($1::text::uuid)::text",
            &[&change_id],
        )?;
        column(&row, 0)
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
        let before = (self.clock)();
        let row = self.client.query_one(
            "SELECT crl_number,
                    floor(extract(epoch FROM this_update))::bigint,
                    floor(extract(epoch FROM next_update))::bigint,
                    floor(extract(epoch FROM expired_certs_on_crl_since))::bigint
             FROM reserve_crl($1::text::uuid, $2, $3)",
            &[&ca_id, &actor, &operation_ref],
        )?;
        let after = (self.clock)();
        // The database chose thisUpdate; refuse a misdated CRL before it can
        // be signed (ADR-0006 condition 6).
        if !this_update_plausible(column(&row, 1)?, before, after, self.max_clock_skew_us) {
            return Err(RevocationStoreError::ClockSkew);
        }
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
    /// The clock the database is checked against: the host clock by
    /// default; an authenticated time source adapter (or a test) may
    /// replace it. Microseconds since the Unix epoch.
    pub fn set_clock_source(&mut self, clock: ClockSource) {
        self.clock = clock;
    }

    /// Bound on |database clock - Rust clock| plus measurement uncertainty
    /// (default `clock::DEFAULT_MAX_CLOCK_SKEW_US`).
    pub fn set_max_clock_skew_us(&mut self, max_skew_us: i64) {
        self.max_clock_skew_us = max_skew_us;
    }

    /// One database clock reading bracketed by two readings of the Rust
    /// core's clock.
    pub fn database_clock(&mut self) -> Result<ClockReading, RevocationStoreError> {
        let before = (self.clock)();
        let row = self.client.query_one(
            "SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
            &[],
        )?;
        let after = (self.clock)();
        Ok(ClockReading::bracket(before, column(&row, 0)?, after))
    }

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
                    (SELECT count(*) FROM overdue_status_changes($1::text::uuid)),
                    (SELECT count(*) FROM precautionary_holds($1::text::uuid) WHERE overdue)",
            &[&ca_id],
        )?;
        let clock = self.database_clock()?;
        Ok(CrlHousekeepingReport {
            abandoned,
            quarantined,
            crl_due: column(&row, 0)?,
            overdue_changes: column(&row, 1)?,
            overdue_precautionary_holds: column(&row, 2)?,
            clock,
            clock_within_bound: clock.within(self.max_clock_skew_us),
        })
    }

    /// Every CA that can publish CRLs (registered issuer certificate,
    /// migration 0033), for a housekeeping job that covers them all.
    pub fn crl_issuing_cas(&mut self) -> Result<Vec<String>, RevocationStoreError> {
        self.client
            .query("SELECT ca_id::text FROM crl_issuing_cas()", &[])?
            .iter()
            .map(|row| column(row, 0))
            .collect()
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
        // Every revocation the snapshot leaves out must be explained by the
        // stored certificate's own expiry (0031 pruning, 0032 check).
        let omitted = self
            .client
            .query(
                "SELECT serial_der_content, not_after_unix, certificate_der
                 FROM crl_pruned_entries($1::text::uuid, $2::bigint)",
                &[&reservation.ca_id(), &number],
            )
            .map_err(|_| CrlError::JournalFailure)?;
        for row in &omitted {
            let serial: Vec<u8> = row.try_get(0).map_err(|_| CrlError::JournalFailure)?;
            let not_after: Option<i64> = row.try_get(1).map_err(|_| CrlError::JournalFailure)?;
            let der: Option<Vec<u8>> = row.try_get(2).map_err(|_| CrlError::JournalFailure)?;
            check_pruned_entry(
                &serial,
                not_after,
                der.as_deref(),
                reservation.this_update_unix(),
            )?;
        }
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
