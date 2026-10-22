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
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

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
    /// A checker rejects a proposal (signed, migration 0039).
    Reject,
    /// The maker withdraws a proposal (signed, migration 0039).
    Withdraw,
    /// The CA's emergency key enrols one admin key (migration 0045).
    BreakGlass,
    /// A CA admin's signed review of a break-glass use (migration 0045).
    Review,
}

/// The two families of CA-administration changes (0024, 0028).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminFamily {
    /// Issuer registration and officer grants (`ca_admin_change`).
    CaAdmin,
    /// Officer credential enrolment and removal (`officer_credential_change`).
    Credential,
    /// CA-admin credential enrolment and removal (0040,
    /// `ca_admin_credential_change`).
    AdminCredential,
}

impl AdminFamily {
    fn as_sql(self) -> &'static str {
        match self {
            Self::CaAdmin => "CA_ADMIN",
            Self::Credential => "CREDENTIAL",
            Self::AdminCredential => "ADMIN_CREDENTIAL",
        }
    }
}

/// A CA-administration change as the maker reviews and signs it.
pub enum AdminChange<'a> {
    RegisterIssuer(&'a Certificate),
    Officer(OfficerGrantAction, &'a OfficerIdentity<'a>),
    /// For a removal, the person and key of the credential being removed.
    Credential(CredentialChangeKind, &'a CredentialContent<'a>),
    /// A CA admin's own WebAuthn key (0040); `officer` names the admin.
    AdminCredential(CredentialChangeKind, &'a CredentialContent<'a>),
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
            Self::AdminCredential(..) => AdminFamily::AdminCredential,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::RegisterIssuer(_) => "REGISTER_ISSUER",
            Self::Officer(action, _) => action.as_sql(),
            Self::Credential(kind, _) => kind.as_sql(),
            Self::AdminCredential(CredentialChangeKind::Enroll, _) => "ENROLL_ADMIN_CREDENTIAL",
            Self::AdminCredential(CredentialChangeKind::Remove, _) => "REMOVE_ADMIN_CREDENTIAL",
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
            Self::Credential(kind, content) | Self::AdminCredential(kind, content) => {
                let (key, digest) = content.reviewed_as(*kind, self.kind())?;
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

/// Which kind of signed change a piece of evidence belongs to (0041).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFamily {
    StatusChange,
    Admin(AdminFamily),
    /// A break-glass use and its reviews (0045); `change_id` is the use.
    BreakGlass,
}

/// The result of re-verifying one signed change offline (0041).
#[derive(Debug)]
pub struct EvidenceFinding {
    pub family: EvidenceFamily,
    pub change_id: String,
    pub result: Result<(), RevocationStoreError>,
}

/// A pending CA-admin change with the content a checker reviews
/// (migration 0044). `content_sha256` is the digest the checker signs,
/// recomputed from the content here and checked against the stored one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAdminChange {
    pub family: AdminFamily,
    pub change_id: String,
    pub kind: &'static str,
    pub certificate_der: Option<Vec<u8>>,
    /// Officer (or, for admin credentials, admin) identity.
    pub officer_issuer: Option<String>,
    pub officer_subject: Option<String>,
    pub credential_id: Option<Vec<u8>>,
    pub person_id: Option<String>,
    pub public_key_sec1: Option<Vec<u8>>,
    pub content_sha256: [u8; 32],
    pub maker_issuer: String,
    pub maker_subject: String,
    pub proposed_at_unix: i64,
    pub maker_signed: bool,
    /// Past the CA's `admin_proposal_max_age_hours` (0052, 0054): it can
    /// only be rejected.
    pub expired: bool,
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

/// A break-glass enrolment of a CA-admin key (migration 0045). It stays
/// open, and housekeeping alerts, until two other admins have reviewed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassUse {
    pub use_id: String,
    pub admin_credential_id: Vec<u8>,
    pub admin_issuer: String,
    pub admin_subject: String,
    pub used_at_unix: i64,
    pub review_by_unix: i64,
    pub reviews: i64,
    pub reviewed: bool,
    pub overdue: bool,
}

/// What a break-glass use enrolled, as a reviewer sees it (migration 0051).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassContent {
    pub use_id: String,
    pub admin_credential_id: Vec<u8>,
    pub admin_issuer: String,
    pub admin_subject: String,
    pub person_id: String,
    pub public_key_sec1: Vec<u8>,
}

/// A break-glass use's content and whether its evidence re-verifies.
pub type BreakGlassEvidence = (BreakGlassContent, Result<(), RevocationStoreError>);

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

impl SignedChallenge {
    /// The WebAuthn challenge to sign: the claim's digest, or its closing
    /// digest for a rejection or withdrawal (domain-separated, 0039).
    pub fn digest(&self) -> Result<[u8; 32], RevocationStoreError> {
        match self.purpose {
            SignedStep::Reject => self.claim.closing_digest("REJECT"),
            SignedStep::Withdraw => self.claim.closing_digest("WITHDRAW"),
            _ => Ok(self.claim.digest()),
        }
        .map_err(|_| RevocationStoreError::InconsistentResult)
    }
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
        "ENROLL_ADMIN_CREDENTIAL" => Ok("ENROLL_ADMIN_CREDENTIAL"),
        "REMOVE_ADMIN_CREDENTIAL" => Ok("REMOVE_ADMIN_CREDENTIAL"),
        _ => Err(RevocationStoreError::InconsistentResult),
    }
}

/// The content digest of a pending CA-admin change, recomputed as in 0024 /
/// 0028 / 0040 (None if the content does not fit its kind).
fn pending_content_digest(ca: &[u8; 16], change: &PendingAdminChange) -> Option<[u8; 32]> {
    match change.kind {
        "REGISTER_ISSUER" => change
            .certificate_der
            .as_ref()
            .map(|der| Sha256::digest(der).into()),
        "GRANT_OFFICER" | "REVOKE_OFFICER" => {
            let action = if change.kind == "GRANT_OFFICER" {
                OfficerGrantAction::Grant
            } else {
                OfficerGrantAction::Revoke
            };
            Some(officer_grant_digest(
                action,
                &OfficerIdentity {
                    issuer: change.officer_issuer.as_deref()?,
                    subject: change.officer_subject.as_deref()?,
                },
            ))
        }
        kind => {
            let credential_kind = match kind {
                "ENROLL_CREDENTIAL" | "ENROLL_ADMIN_CREDENTIAL" => CredentialChangeKind::Enroll,
                _ => CredentialChangeKind::Remove,
            };
            let key: [u8; 33] = change.public_key_sec1.as_deref()?.try_into().ok()?;
            Some(
                CredentialChange {
                    kind: credential_kind,
                    ca_id: *ca,
                    credential_id: change.credential_id.as_deref()?,
                    officer_issuer: change.officer_issuer.as_deref()?,
                    officer_subject: change.officer_subject.as_deref()?,
                    person_id: change.person_id.as_deref()?,
                    public_key: &key,
                }
                .digest_with_kind(kind),
            )
        }
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
        self.reviewed_as(kind, kind.as_sql())
    }

    /// As `reviewed`, with the digest computed under `kind_sql` (the
    /// CA-admin credential kinds of migration 0040).
    fn reviewed_as(
        &self,
        kind: CredentialChangeKind,
        kind_sql: &str,
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
        Ok((key, change.digest_with_kind(kind_sql)))
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
    /// Break-glass uses (0045) not yet reviewed by two other admins, and
    /// those of them past their review deadline.
    pub open_breakglass_uses: i64,
    pub overdue_breakglass_uses: i64,
    /// Challenges deleted because they expired unused more than
    /// `CHALLENGE_RETENTION_DAYS` ago (migration 0053); housekeeping only.
    pub purged_challenges: i64,
    /// CA-admin proposals past `admin_proposal_max_age_hours` (0052, 0054):
    /// no longer approvable, to be rejected.
    pub stale_admin_proposals: i64,
    /// Certificates whose `not_after` was read from the stored DER and
    /// recorded (migration 0055); housekeeping only.
    pub backfilled_not_after: i64,
    /// Certificates still without `not_after` whose stored DER does not
    /// parse or names another serial: never guessed, so never pruned.
    pub unreadable_certificates: i64,
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
            || self.open_breakglass_uses > 0
            || self.stale_admin_proposals > 0
            || self.unreadable_certificates > 0
            || !self.clock_within_bound
    }
}

/// How long challenges that expired unused are kept before housekeeping
/// purges them (migration 0053; at least 7 days).
pub const CHALLENGE_RETENTION_DAYS: i32 = 30;

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

    /// Asks for a single-use challenge to reject (a checker other than the
    /// maker) or withdraw (the maker) a proposal with a signature
    /// (migration 0039). `step` is `SignedStep::Reject` or `Withdraw`.
    pub fn issue_close_challenge(
        &mut self,
        change_id: &str,
        actor: &OfficerIdentity<'_>,
        step: SignedStep,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let purpose = match step {
            SignedStep::Reject => "REJECT",
            SignedStep::Withdraw => "WITHDRAW",
            _ => return Err(RevocationStoreError::SignedApprovalRefused),
        };
        let row = self.client.query_one(
            "SELECT issue_close_challenge($1, $2::text::uuid, $3, $4, $5)::text",
            &[
                &purpose,
                &change_id,
                &actor.issuer,
                &actor.subject,
                &ttl_seconds,
            ],
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
            "PRECAUTION" => SignedStep::Precaution,
            "REJECT" => SignedStep::Reject,
            "WITHDRAW" => SignedStep::Withdraw,
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
            &challenge.digest()?,
            stored_count,
        )
        .map_err(RevocationStoreError::InvalidAssertion)?;
        // The database cannot verify ECDSA: before a checker's approval
        // completes a change, the maker's stored signature is re-verified
        // here, so a proposal stored with a forged maker signature cannot
        // be completed through the Rust core.
        if challenge.purpose == SignedStep::Approve {
            self.reverify_status_evidence(&hex_uuid(&challenge.claim.change_id), rp, true)?;
        }
        let function = match challenge.purpose {
            SignedStep::Propose => "propose_signed_status_change",
            SignedStep::Approve => "approve_signed_status_change",
            SignedStep::Precaution => "apply_precautionary_hold",
            SignedStep::Reject | SignedStep::Withdraw => "close_signed_status_change",
            // Break-glass steps are CA-admin claims, never status changes.
            SignedStep::BreakGlass | SignedStep::Review => {
                return Err(RevocationStoreError::InconsistentResult)
            }
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

    /// Re-verifies the stored evidence of a signed change offline: every
    /// assertion against its enrolled key and the claim rebuilt from its
    /// challenge. Complete evidence is a maker and a checker with distinct
    /// keys and persons, a maker and a rejecting checker (distinct too), a
    /// maker and their own withdrawal (0039), or the single signature of a
    /// precautionary hold (0036). Exposes an assertion that reached the
    /// database without the Rust core.
    pub fn reverify_signed_change(
        &mut self,
        change_id: &str,
        rp: &RelyingParty<'_>,
    ) -> Result<(), RevocationStoreError> {
        self.reverify_status_evidence(change_id, rp, false)
    }

    /// `reverify_signed_change`, or for a still-open proposal (`pending`)
    /// its maker signature alone.
    /// Re-verifies a pending proposal's stored maker signature (as before
    /// an approval is written), so a checker can be told before signing.
    pub fn verify_pending_maker(
        &mut self,
        change_id: &str,
        rp: &RelyingParty<'_>,
    ) -> Result<(), RevocationStoreError> {
        self.reverify_status_evidence(change_id, rp, true)
    }

    fn reverify_status_evidence(
        &mut self,
        change_id: &str,
        rp: &RelyingParty<'_>,
        pending: bool,
    ) -> Result<(), RevocationStoreError> {
        let rows = self.client.query(
            "SELECT role, challenge_id::text, public_key_sec1, person_id, claim_sha256,
                    authenticator_data, client_data_json, signature_der
             FROM status_change_signatures($1::text::uuid)",
            &[&change_id],
        )?;
        if !(1..=2).contains(&rows.len()) {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        let mut keys = Vec::new();
        let mut persons = Vec::new();
        let mut steps = Vec::new();
        for row in &rows {
            let challenge = self.signed_challenge(&column::<String>(row, 1)?)?;
            steps.push(challenge.purpose);
            let digest = challenge.digest()?;
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
            [SignedStep::Propose] => pending,
            [SignedStep::Precaution] => !pending,
            [SignedStep::Propose, SignedStep::Approve | SignedStep::Reject] => {
                keys[0] != keys[1] && persons[0] != persons[1]
            }
            [SignedStep::Propose, SignedStep::Withdraw] => persons[0] == persons[1],
            _ => false,
        };
        complete
            .then_some(())
            .ok_or(RevocationStoreError::SignedApprovalRefused)
    }

    /// Every change of `ca_id` that carries signatures (status changes and
    /// CA administration), each re-verified offline like
    /// `reverify_signed_change` / `reverify_admin_change` (migration 0041:
    /// `trust_audit_verifier` may run this read-only). A failure on one
    /// change is reported, not raised, so one forged record cannot hide
    /// the others; only reading the index itself fails the call. An open
    /// proposal is checked on its maker signature alone.
    pub fn audit_signed_evidence(
        &mut self,
        ca_id: &str,
        rp: &RelyingParty<'_>,
    ) -> Result<Vec<EvidenceFinding>, RevocationStoreError> {
        let index: Vec<(String, String, String)> = self
            .client
            .query(
                "SELECT family, change_id::text, status
                 FROM signed_evidence_index($1::text::uuid)",
                &[&ca_id],
            )?
            .iter()
            .map(|row| Ok((column(row, 0)?, column(row, 1)?, column(row, 2)?)))
            .collect::<Result<_, RevocationStoreError>>()?;
        let mut findings = Vec::with_capacity(index.len());
        for (family, change_id, status) in index {
            let pending = status == "PROPOSED";
            let family = match family.as_str() {
                "STATUS_CHANGE" => EvidenceFamily::StatusChange,
                "CA_ADMIN" => EvidenceFamily::Admin(AdminFamily::CaAdmin),
                "CREDENTIAL" => EvidenceFamily::Admin(AdminFamily::Credential),
                "ADMIN_CREDENTIAL" => EvidenceFamily::Admin(AdminFamily::AdminCredential),
                _ => return Err(RevocationStoreError::InconsistentResult),
            };
            let result = match family {
                EvidenceFamily::StatusChange => {
                    self.reverify_status_evidence(&change_id, rp, pending)
                }
                EvidenceFamily::Admin(admin) => {
                    self.reverify_admin_evidence(admin, &change_id, rp, pending)
                }
                EvidenceFamily::BreakGlass => return Err(RevocationStoreError::InconsistentResult),
            };
            findings.push(EvidenceFinding {
                family,
                change_id,
                result,
            });
        }
        let rows = self.client.query(
            "SELECT use_id::text, role, challenge_id::text, public_key_sec1, person_id,
                    claim_sha256, authenticator_data, client_data_json, signature_der,
                    admin_credential_id, admin_issuer, admin_subject, admin_person_id,
                    admin_public_key_sec1, use_claim_sha256, reviewed
             FROM breakglass_evidence($1::text::uuid)",
            &[&ca_id],
        )?;
        let mut start = 0;
        while start < rows.len() {
            let use_id: String = column(&rows[start], 0)?;
            let mut end = start;
            while end < rows.len() && column::<String>(&rows[end], 0)? == use_id {
                end += 1;
            }
            let result = self.reverify_breakglass_use(&use_id, &rows[start..end], rp);
            findings.push(EvidenceFinding {
                family: EvidenceFamily::BreakGlass,
                change_id: use_id,
                result,
            });
            start = end;
        }
        Ok(findings)
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

    /// The CA's pending CA-admin changes with their content (migration
    /// 0044), oldest first. Each content digest is recomputed from the
    /// content and must equal the stored one (otherwise the whole answer is
    /// refused as inconsistent rather than shown to a checker).
    pub fn pending_admin_changes(
        &mut self,
        ca_id: &str,
    ) -> Result<Vec<PendingAdminChange>, RevocationStoreError> {
        let ca = parse_uuid(ca_id).ok_or(RevocationStoreError::InconsistentResult)?;
        let rows = self.client.query(
            "SELECT family, change_id::text, kind, certificate_der, officer_issuer,
                    officer_subject, credential_id, person_id, public_key_sec1, content_sha256,
                    maker_issuer, maker_subject, extract(epoch FROM proposed_at)::bigint,
                    maker_signed
             FROM pending_admin_changes($1::text::uuid)",
            &[&ca_id],
        )?;
        let stale = self.stale_admin_proposals(ca_id)?;
        rows.iter()
            .map(|row| {
                let family = match column::<String>(row, 0)?.as_str() {
                    "CA_ADMIN" => AdminFamily::CaAdmin,
                    "CREDENTIAL" => AdminFamily::Credential,
                    "ADMIN_CREDENTIAL" => AdminFamily::AdminCredential,
                    _ => return Err(RevocationStoreError::InconsistentResult),
                };
                let change = PendingAdminChange {
                    family,
                    change_id: column(row, 1)?,
                    kind: admin_kind(&column::<String>(row, 2)?)?,
                    certificate_der: column(row, 3)?,
                    officer_issuer: column(row, 4)?,
                    officer_subject: column(row, 5)?,
                    credential_id: column(row, 6)?,
                    person_id: column(row, 7)?,
                    public_key_sec1: column(row, 8)?,
                    content_sha256: hash_column(row, 9)?,
                    maker_issuer: column(row, 10)?,
                    maker_subject: column(row, 11)?,
                    proposed_at_unix: column(row, 12)?,
                    maker_signed: column(row, 13)?,
                    expired: false,
                };
                let change = PendingAdminChange {
                    expired: stale.contains(&(family, change.change_id.clone())),
                    ..change
                };
                (pending_content_digest(&ca, &change) == Some(change.content_sha256))
                    .then_some(change)
                    .ok_or(RevocationStoreError::InconsistentResult)
            })
            .collect()
    }

    /// The CA's pending CA-admin changes past `admin_proposal_max_age_hours`
    /// (migration 0054), which can only be rejected.
    pub fn stale_admin_proposals(
        &mut self,
        ca_id: &str,
    ) -> Result<Vec<(AdminFamily, String)>, RevocationStoreError> {
        self.client
            .query(
                "SELECT family, change_id::text FROM stale_admin_proposals($1::text::uuid)",
                &[&ca_id],
            )?
            .iter()
            .map(|row| {
                let family = match column::<String>(row, 0)?.as_str() {
                    "CA_ADMIN" => AdminFamily::CaAdmin,
                    "CREDENTIAL" => AdminFamily::Credential,
                    "ADMIN_CREDENTIAL" => AdminFamily::AdminCredential,
                    _ => return Err(RevocationStoreError::InconsistentResult),
                };
                Ok((family, column(row, 1)?))
            })
            .collect()
    }

    /// The CA of a CA-admin change (migration 0050), None if unknown, so a
    /// caller can check its scope before a challenge is written.
    pub fn admin_change_ca(
        &mut self,
        family: AdminFamily,
        change_id: &str,
    ) -> Result<Option<String>, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT admin_change_ca($1, $2::text::uuid)::text",
            &[&family.as_sql(), &change_id],
        )?;
        column(&row, 0)
    }

    /// The CA of a break-glass use (migration 0050), None if unknown.
    pub fn breakglass_use_ca(
        &mut self,
        use_id: &str,
    ) -> Result<Option<String>, RevocationStoreError> {
        let row = self
            .client
            .query_one("SELECT breakglass_use_ca($1::text::uuid)::text", &[&use_id])?;
        column(&row, 0)
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

    /// Asks for a single-use challenge to reject a CA-admin change with a
    /// signature (a CA admin other than the maker; migration 0042).
    pub fn issue_admin_rejection_challenge(
        &mut self,
        family: AdminFamily,
        change_id: &str,
        checker: &OfficerIdentity<'_>,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT issue_ca_admin_challenge('REJECT', NULL, $1, NULL, NULL, $2::text::uuid,
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
            "REJECT" => (SignedStep::Reject, "REJECT"),
            "BREAK_GLASS" => (SignedStep::BreakGlass, "BREAK_GLASS"),
            "REVIEW" => (SignedStep::Review, "REVIEW"),
            _ => return Err(RevocationStoreError::InconsistentResult),
        };
        let family = match column::<String>(row, 2)?.as_str() {
            "CA_ADMIN" => "CA_ADMIN",
            "CREDENTIAL" => "CREDENTIAL",
            "ADMIN_CREDENTIAL" => "ADMIN_CREDENTIAL",
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
        let credential = self.admin_signer(&challenge, credential_id, rp)?;
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
            (SignedStep::Approve | SignedStep::Reject, None) => None,
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
        // As for status changes: the maker's stored signature is re-verified
        // before a checker's approval completes the change (the database
        // cannot verify ECDSA).
        if challenge.purpose == SignedStep::Approve {
            let family = match challenge.claim.family {
                "CA_ADMIN" => AdminFamily::CaAdmin,
                "CREDENTIAL" => AdminFamily::Credential,
                "ADMIN_CREDENTIAL" => AdminFamily::AdminCredential,
                _ => return Err(RevocationStoreError::InconsistentResult),
            };
            let change_id = challenge
                .claim
                .change_id
                .as_ref()
                .map(hex_uuid)
                .ok_or(RevocationStoreError::InconsistentResult)?;
            self.reverify_admin_evidence(family, &change_id, rp, true)?;
        }
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
                let function = if challenge.purpose == SignedStep::Reject {
                    "reject_signed_admin_change"
                } else {
                    "approve_signed_admin_change"
                };
                self.client.query_one(
                    &format!("SELECT {function}($1::text::uuid, $2, $3, $4, $5)"),
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

    /// The active admin key `credential_id` of the challenge's actor, for an
    /// unconsumed challenge; anything else is refused before verifying.
    fn admin_signer(
        &mut self,
        challenge: &AdminChallenge,
        credential_id: &[u8],
        rp: &RelyingParty<'_>,
    ) -> Result<StoredCredential, RevocationStoreError> {
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
        // A key enrolled by a break-glass use signs only while that use's
        // evidence re-verifies: a forged emergency signature (which the
        // database cannot detect) leaves a key that signs nothing here.
        if !self.breakglass_enrolment_verifies(&ca_text, credential_id, rp)? {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        Ok(credential)
    }

    /// True unless `credential_id` was enrolled by a break-glass use of the
    /// CA whose evidence does not re-verify (migrations 0045, 0051).
    fn breakglass_enrolment_verifies(
        &mut self,
        ca_text: &str,
        credential_id: &[u8],
        rp: &RelyingParty<'_>,
    ) -> Result<bool, RevocationStoreError> {
        let rows = self.client.query(
            "SELECT use_id::text, role, challenge_id::text, public_key_sec1, person_id,
                    claim_sha256, authenticator_data, client_data_json, signature_der,
                    admin_credential_id, admin_issuer, admin_subject, admin_person_id,
                    admin_public_key_sec1, use_claim_sha256, reviewed
             FROM breakglass_evidence($1::text::uuid)
             WHERE admin_credential_id = $2",
            &[&ca_text, &credential_id],
        )?;
        let mut uses: Vec<String> = Vec::new();
        for row in &rows {
            let use_id: String = column(row, 0)?;
            if !uses.contains(&use_id) {
                uses.push(use_id);
            }
        }
        for use_id in uses {
            let evidence: Vec<Row> = rows
                .iter()
                .filter(|row| row.try_get::<_, String>(0).ok().as_deref() == Some(use_id.as_str()))
                .cloned()
                .collect();
            if self
                .reverify_breakglass_use(&use_id, &evidence, rp)
                .is_err()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// DBA bootstrap of the CA's break-glass key (migration 0045): needs a
    /// superuser login, never a service. The key is curve-checked and
    /// canonicalised; the database refuses an officer or admin key, and
    /// (0046) a custodian person who is an officer or admin of the CA.
    pub fn enroll_breakglass_credential(
        &mut self,
        ca_id: &str,
        credential_id: &[u8],
        holder_label: &str,
        holder_person_id: &str,
        public_key_sec1: &[u8],
    ) -> Result<(), RevocationStoreError> {
        let key = canonical_officer_key(public_key_sec1)
            .map_err(RevocationStoreError::InvalidCredential)?;
        self.client.execute(
            "SELECT enroll_breakglass_credential($1::text::uuid, $2, $3, $4, $5)",
            &[
                &ca_id,
                &credential_id,
                &holder_label,
                &holder_person_id,
                &&key[..],
            ],
        )?;
        Ok(())
    }

    /// Asks for a single-use challenge for the break-glass key to enrol the
    /// admin key in `content` (migration 0045). Refused unless the CA
    /// requires signed administration and has fewer than two admin keys.
    pub fn issue_breakglass_challenge(
        &mut self,
        breakglass_credential_id: &[u8],
        content: &CredentialContent<'_>,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let (_, digest) =
            content.reviewed_as(CredentialChangeKind::Enroll, "ENROLL_ADMIN_CREDENTIAL")?;
        let row = self.client.query_one(
            "SELECT issue_breakglass_challenge($1::text::uuid, $2, $3, $4)::text",
            &[
                &content.ca_id,
                &breakglass_credential_id,
                &&digest[..],
                &ttl_seconds,
            ],
        )?;
        column(&row, 0)
    }

    /// Submits the break-glass enrolment of `content` (the admin key the
    /// holder reviewed, which must be the signed one). The assertion is
    /// verified against the claim rebuilt from the stored challenge and the
    /// enrolled break-glass key before anything is written; the database
    /// re-checks the rest (migration 0045). Returns the use id.
    pub fn submit_breakglass(
        &mut self,
        challenge_id: &str,
        breakglass_credential_id: &[u8],
        assertion: &Assertion<'_>,
        rp: &RelyingParty<'_>,
        content: &CredentialContent<'_>,
    ) -> Result<String, RevocationStoreError> {
        let challenge = self.admin_challenge(challenge_id)?;
        let ca_text = hex_uuid(&challenge.claim.ca_id);
        let rows = self.client.query(
            "SELECT holder_label, public_key_sec1, sign_count, active
             FROM breakglass_credential_for($1::text::uuid, $2)",
            &[&ca_text, &breakglass_credential_id],
        )?;
        let row = rows
            .first()
            .ok_or(RevocationStoreError::SignedApprovalRefused)?;
        let holder: String = column(row, 0)?;
        let key: Vec<u8> = column(row, 1)?;
        let sign_count: i64 = column(row, 2)?;
        let active: bool = column(row, 3)?;
        let (admin_key, digest) =
            content.reviewed_as(CredentialChangeKind::Enroll, "ENROLL_ADMIN_CREDENTIAL")?;
        if challenge.purpose != SignedStep::BreakGlass
            || challenge.consumed
            || !active
            || challenge.actor_subject != holder
            || content.ca_id != ca_text
            || digest != challenge.claim.content_sha256
        {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        let stored_count =
            u32::try_from(sign_count).map_err(|_| RevocationStoreError::InconsistentResult)?;
        verify_assertion(assertion, rp, &key, &challenge.claim.digest(), stored_count)
            .map_err(RevocationStoreError::InvalidAssertion)?;
        let row = self.client.query_one(
            "SELECT breakglass_enroll_admin_credential($1::text::uuid, $2, $3, $4, $5,
                                                      $6, $7, $8, $9, $10)::text",
            &[
                &challenge_id,
                &breakglass_credential_id,
                &assertion.authenticator_data,
                &assertion.client_data_json,
                &assertion.signature_der,
                &content.credential_id,
                &content.officer.issuer,
                &content.officer.subject,
                &content.person_id,
                &&admin_key[..],
            ],
        )?;
        column(&row, 0)
    }

    /// Asks for a single-use challenge for `reviewer` (a CA admin other than
    /// the one enrolled) to review a break-glass use (migration 0045).
    pub fn issue_breakglass_review_challenge(
        &mut self,
        use_id: &str,
        reviewer: &OfficerIdentity<'_>,
        ttl_seconds: i32,
    ) -> Result<String, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT issue_breakglass_review_challenge($1::text::uuid, $2, $3, $4)::text",
            &[&use_id, &reviewer.issuer, &reviewer.subject, &ttl_seconds],
        )?;
        column(&row, 0)
    }

    /// Submits a signed review of a break-glass use, verified in the Rust
    /// core first like any CA-admin signature. Returns true once the use
    /// has its two reviews.
    pub fn submit_breakglass_review(
        &mut self,
        challenge_id: &str,
        credential_id: &[u8],
        assertion: &Assertion<'_>,
        rp: &RelyingParty<'_>,
    ) -> Result<bool, RevocationStoreError> {
        let challenge = self.admin_challenge(challenge_id)?;
        if challenge.purpose != SignedStep::Review {
            return Err(RevocationStoreError::SignedApprovalRefused);
        }
        let credential = self.admin_signer(&challenge, credential_id, rp)?;
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
        // The use's stored evidence (emergency signature and reviews so far)
        // must re-verify before this review is written: a forged earlier
        // review cannot be completed by an honest one.
        let use_id = challenge
            .claim
            .change_id
            .as_ref()
            .map(hex_uuid)
            .ok_or(RevocationStoreError::InconsistentResult)?;
        match self.breakglass_use_evidence(&use_id, rp)? {
            Some((_, Ok(()))) => {}
            Some((_, Err(error))) => return Err(error),
            None => return Err(RevocationStoreError::SignedApprovalRefused),
        }
        let row = self.client.query_one(
            "SELECT review_breakglass_use($1::text::uuid, $2, $3, $4, $5)",
            &[
                &challenge_id,
                &credential_id,
                &assertion.authenticator_data,
                &assertion.client_data_json,
                &assertion.signature_der,
            ],
        )?;
        match column::<String>(&row, 0)?.as_str() {
            "REVIEWED" => Ok(true),
            "PENDING_SECOND_REVIEW" => Ok(false),
            _ => Err(RevocationStoreError::InconsistentResult),
        }
    }

    /// The CA's break-glass uses, oldest first (migration 0045).
    pub fn breakglass_uses(
        &mut self,
        ca_id: &str,
    ) -> Result<Vec<BreakGlassUse>, RevocationStoreError> {
        self.client
            .query(
                "SELECT use_id::text, admin_credential_id, admin_issuer, admin_subject,
                        extract(epoch FROM used_at)::bigint,
                        extract(epoch FROM review_by)::bigint, reviews, reviewed, overdue
                 FROM breakglass_uses($1::text::uuid)",
                &[&ca_id],
            )?
            .iter()
            .map(|row| {
                Ok(BreakGlassUse {
                    use_id: column(row, 0)?,
                    admin_credential_id: column(row, 1)?,
                    admin_issuer: column(row, 2)?,
                    admin_subject: column(row, 3)?,
                    used_at_unix: column(row, 4)?,
                    review_by_unix: column(row, 5)?,
                    reviews: column(row, 6)?,
                    reviewed: column(row, 7)?,
                    overdue: column(row, 8)?,
                })
            })
            .collect()
    }

    /// A break-glass use's enrolled content and the result of re-verifying
    /// its evidence (emergency signature and reviews so far) in the Rust
    /// core (migration 0051, `trust_ca_admin` or `trust_audit_verifier`).
    /// None if the use is unknown.
    pub fn breakglass_use_evidence(
        &mut self,
        use_id: &str,
        rp: &RelyingParty<'_>,
    ) -> Result<Option<BreakGlassEvidence>, RevocationStoreError> {
        let Some(ca_id) = self.breakglass_use_ca(use_id)? else {
            return Ok(None);
        };
        let rows: Vec<Row> = self
            .client
            .query(
                "SELECT use_id::text, role, challenge_id::text, public_key_sec1, person_id,
                        claim_sha256, authenticator_data, client_data_json, signature_der,
                        admin_credential_id, admin_issuer, admin_subject, admin_person_id,
                        admin_public_key_sec1, use_claim_sha256, reviewed
                 FROM breakglass_evidence($1::text::uuid)",
                &[&ca_id],
            )?
            .into_iter()
            .filter(|row| row.try_get::<_, String>(0).ok().as_deref() == Some(use_id))
            .collect();
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let content = BreakGlassContent {
            use_id: use_id.to_owned(),
            admin_credential_id: column(first, 9)?,
            admin_issuer: column(first, 10)?,
            admin_subject: column(first, 11)?,
            person_id: column(first, 12)?,
            public_key_sec1: column(first, 13)?,
        };
        let result = self.reverify_breakglass_use(use_id, &rows, rp);
        Ok(Some((content, result)))
    }

    /// Re-verifies a break-glass use offline (migration 0045): the
    /// break-glass signature over the claim naming the enrolled admin key,
    /// and each review over the claim naming the use and its claim, by
    /// admins other than the enrolled one with distinct keys and persons;
    /// a reviewed use has exactly two reviews.
    fn reverify_breakglass_use(
        &mut self,
        use_id: &str,
        rows: &[Row],
        rp: &RelyingParty<'_>,
    ) -> Result<(), RevocationStoreError> {
        let mut reviewers: Vec<(Vec<u8>, String)> = Vec::new();
        let mut uses = 0;
        let mut reviewed = false;
        for row in rows {
            let challenge = self.admin_challenge(&column::<String>(row, 2)?)?;
            let claim = &challenge.claim;
            let digest = claim.digest();
            let key: Vec<u8> = column(row, 3)?;
            let admin_person: String = column(row, 12)?;
            let use_claim = hash_column(row, 14)?;
            reviewed = column(row, 15)?;
            let content_ok = match (column::<String>(row, 1)?.as_str(), challenge.purpose) {
                ("BREAK_GLASS", SignedStep::BreakGlass) => {
                    uses += 1;
                    let admin_key: Vec<u8> = column(row, 13)?;
                    let credential_id: Vec<u8> = column(row, 9)?;
                    let issuer: String = column(row, 10)?;
                    let subject: String = column(row, 11)?;
                    let ca_text = hex_uuid(&claim.ca_id);
                    let content = CredentialContent {
                        ca_id: &ca_text,
                        credential_id: &credential_id,
                        officer: &OfficerIdentity {
                            issuer: &issuer,
                            subject: &subject,
                        },
                        person_id: &admin_person,
                        public_key_sec1: &admin_key,
                    };
                    let (_, content_digest) = content
                        .reviewed_as(CredentialChangeKind::Enroll, "ENROLL_ADMIN_CREDENTIAL")?;
                    claim.change_id.is_none()
                        && content_digest == claim.content_sha256
                        && digest == use_claim
                }
                ("REVIEW", SignedStep::Review) => {
                    let person: String = column(row, 4)?;
                    let distinct = person != admin_person
                        && reviewers.iter().all(|(k, p)| *k != key && *p != person);
                    reviewers.push((key.clone(), person));
                    distinct
                        && claim.change_id.as_ref().map(hex_uuid).as_deref() == Some(use_id)
                        && claim.content_sha256 == use_claim
                }
                _ => false,
            };
            if !content_ok || hash_column(row, 5)? != digest {
                return Err(RevocationStoreError::SignedApprovalRefused);
            }
            let authenticator_data: Vec<u8> = column(row, 6)?;
            let client_data_json: Vec<u8> = column(row, 7)?;
            let signature_der: Vec<u8> = column(row, 8)?;
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
        }
        let complete = uses == 1
            && if reviewed {
                reviewers.len() == 2
            } else {
                reviewers.len() < 2
            };
        complete
            .then_some(())
            .ok_or(RevocationStoreError::SignedApprovalRefused)
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
        self.reverify_admin_evidence(family, change_id, rp, false)
    }

    /// Re-verifies a pending CA-admin proposal's stored maker signature (as
    /// before an approval is written), so a checker can be told before
    /// signing.
    pub fn verify_pending_admin_maker(
        &mut self,
        family: AdminFamily,
        change_id: &str,
        rp: &RelyingParty<'_>,
    ) -> Result<(), RevocationStoreError> {
        self.reverify_admin_evidence(family, change_id, rp, true)
    }

    /// `reverify_admin_change`, or for a still-open proposal (`pending`)
    /// its maker signature alone.
    fn reverify_admin_evidence(
        &mut self,
        family: AdminFamily,
        change_id: &str,
        rp: &RelyingParty<'_>,
        pending: bool,
    ) -> Result<(), RevocationStoreError> {
        let rows = self.client.query(
            "SELECT role, challenge_id::text, public_key_sec1, person_id, claim_sha256,
                    authenticator_data, client_data_json, signature_der, change_ca::text,
                    change_kind, change_content_sha256
             FROM ca_admin_signatures($1, $2::text::uuid)",
            &[&family.as_sql(), &change_id],
        )?;
        if rows.len() != if pending { 1 } else { 2 } {
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
                SignedStep::Approve | SignedStep::Reject => {
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
        let complete = if pending {
            steps == [SignedStep::Propose]
        } else {
            (steps == [SignedStep::Propose, SignedStep::Approve]
                || steps == [SignedStep::Propose, SignedStep::Reject])
                && keys[0] != keys[1]
                && persons[0] != persons[1]
        };
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
        let (backfilled, unreadable) = self.backfill_not_after(ca_id)?;
        let purged = self.client.query_one(
            "SELECT purge_expired_challenges($1::text::uuid, $2)",
            &[&ca_id, &CHALLENGE_RETENTION_DAYS],
        )?;
        let row = self.client.query_one(
            "SELECT crl_due($1::text::uuid),
                    (SELECT count(*) FROM overdue_status_changes($1::text::uuid)),
                    (SELECT count(*) FROM precautionary_holds($1::text::uuid) WHERE overdue),
                    (SELECT count(*) FROM breakglass_uses($1::text::uuid) WHERE NOT reviewed),
                    (SELECT count(*) FROM breakglass_uses($1::text::uuid) WHERE overdue),
                    (SELECT count(*) FROM stale_admin_proposals($1::text::uuid))",
            &[&ca_id],
        )?;
        let clock = self.database_clock()?;
        Ok(CrlHousekeepingReport {
            abandoned,
            quarantined,
            crl_due: column(&row, 0)?,
            overdue_changes: column(&row, 1)?,
            overdue_precautionary_holds: column(&row, 2)?,
            open_breakglass_uses: column(&row, 3)?,
            overdue_breakglass_uses: column(&row, 4)?,
            purged_challenges: column(&purged, 0)?,
            stale_admin_proposals: column(&row, 5)?,
            backfilled_not_after: backfilled,
            unreadable_certificates: unreadable,
            clock,
            clock_within_bound: clock.within(self.max_clock_skew_us),
        })
    }

    /// Records `not_after` for the CA's certificates stored without it
    /// (migration 0055), read from each stored DER after checking that it
    /// parses and names the stored serial. Returns how many were recorded
    /// and how many remain unreadable (up to 1000 per call).
    pub fn backfill_not_after(&mut self, ca_id: &str) -> Result<(i64, i64), RevocationStoreError> {
        let rows = self.client.query(
            "SELECT serial_der_content, certificate_der
             FROM certificates_without_not_after($1::text::uuid, 1000)",
            &[&ca_id],
        )?;
        let (mut recorded, mut unreadable) = (0, 0);
        for row in &rows {
            let serial: Vec<u8> = column(row, 0)?;
            let der: Vec<u8> = column(row, 1)?;
            let not_after = Certificate::from_der(&der).ok().and_then(|certificate| {
                (certificate.tbs_certificate.serial_number.as_bytes() == serial.as_slice())
                    .then(|| {
                        i64::try_from(
                            certificate
                                .tbs_certificate
                                .validity
                                .not_after
                                .to_unix_duration()
                                .as_secs(),
                        )
                        .ok()
                    })
                    .flatten()
            });
            let Some(not_after) = not_after else {
                unreadable += 1;
                continue;
            };
            let row = self.client.query_one(
                "SELECT record_certificate_not_after($1::text::uuid, $2,
                                                    to_timestamp($3::bigint))",
                &[&ca_id, &serial, &not_after],
            )?;
            if column::<bool>(&row, 0)? {
                recorded += 1;
            }
        }
        Ok((recorded, unreadable))
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
