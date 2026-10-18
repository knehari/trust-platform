//! Synchronous PostgreSQL adapter for certificate status changes and the CRL
//! journal, for **laboratory integration** only.
//!
//! Officer identities `(issuer, subject)` and CRL actors must be established by
//! a trusted identity boundary; this module authenticates nobody, owns no keys
//! and signs nothing. Every rule applied here is re-checked by migrations
//! 0014/0015, which remain the authority.

use crate::crl::{CrlEntry, CrlError, CrlReservation};
use crate::crl_orchestrator::{CrlJournal, CrlPlan};
use crate::revocation::{CertificateStatus, OfficerIdentity, RevocationReason, StatusAction};
use crate::revocation_policy::{decide_status_change, StatusChangeError};
use crate::serial::SerialNumber;
use postgres::{error::SqlState, Client, Error as PgError, NoTls};

#[derive(Debug)]
pub enum RevocationStoreError {
    Database(PgError),
    Denied(StatusChangeError),
    InconsistentResult,
}

impl From<PgError> for RevocationStoreError {
    fn from(value: PgError) -> Self {
        Self::Database(value)
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

    pub fn status(
        &mut self,
        ca_id: &str,
        serial: &SerialNumber,
    ) -> Result<CertificateStatus, RevocationStoreError> {
        let row = self.client.query_one(
            "SELECT certificate_status($1::text::uuid, $2)",
            &[&ca_id, &serial.as_der_content()],
        )?;
        let value: String = row.get(0);
        CertificateStatus::from_sql(&value).ok_or(RevocationStoreError::InconsistentResult)
    }

    /// Reads the status and the CA's suspension policy, applies the pure
    /// transition rules, and only then calls the database function (which
    /// re-checks everything). Returns the change id.
    pub fn propose(
        &mut self,
        ca_id: &str,
        serial: &SerialNumber,
        action: StatusAction,
        reason: Option<RevocationReason>,
        invalidity_at_unix: Option<i64>,
        maker: &OfficerIdentity<'_>,
    ) -> Result<String, RevocationStoreError> {
        let current = self.status(ca_id, serial)?;
        let allowed: bool = self
            .client
            .query_one(
                "SELECT COALESCE((SELECT suspension_allowed FROM ca_revocation_policy
                                  WHERE ca_id = $1::text::uuid), false)",
                &[&ca_id],
            )?
            .get(0);
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
        Ok(row.get(0))
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
        let number: i64 = row.get(0);
        let this_update_unix: i64 = row.get(1);
        let next_update_unix: i64 = row.get(2);
        let expired_certs_on_crl_since_unix: Option<i64> = row.get(3);

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
            let serial_bytes: Vec<u8> = r.get(0);
            let reason_code: i16 = r.get(2);
            entries.push(CrlEntry {
                serial: SerialNumber::from_positive_der_content(&serial_bytes)
                    .map_err(|_| RevocationStoreError::InconsistentResult)?,
                revoked_at_unix: r.get(1),
                reason: RevocationReason::from_code(reason_code)
                    .map_err(|_| RevocationStoreError::InconsistentResult)?,
                invalidity_at_unix: r.get(3),
            });
        }
        Ok(CrlReservation {
            ca_id: ca_id.to_owned(),
            crl_number: u64::try_from(number)
                .map_err(|_| RevocationStoreError::InconsistentResult)?,
            this_update_unix,
            next_update_unix,
            entries,
            expired_certs_on_crl_since_unix,
        })
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
        Ok(row.get(0))
    }
}

impl CrlJournal for PgRevocationStore {
    fn record_intent(&mut self, plan: &CrlPlan<'_>, tbs_sha256: &[u8; 32]) -> Result<(), CrlError> {
        let number =
            i64::try_from(plan.reservation.crl_number).map_err(|_| CrlError::JournalFailure)?;
        match self.client.query_one(
            "SELECT record_crl_intent($1::text::uuid, $2::bigint, $3, $4)",
            &[
                &plan.reservation.ca_id,
                &number,
                &plan.operation_ref,
                &&tbs_sha256[..],
            ],
        ) {
            Ok(_) => Ok(()),
            // The row is no longer RESERVED (or the operation differs): a replay.
            Err(e) if e.code() == Some(&SqlState::CHECK_VIOLATION) => {
                Err(CrlError::ReplayedOrAmbiguousIntent)
            }
            Err(_) => Err(CrlError::JournalFailure),
        }
    }

    fn mark_uncertain(&mut self, plan: &CrlPlan<'_>) -> Result<(), CrlError> {
        let number =
            i64::try_from(plan.reservation.crl_number).map_err(|_| CrlError::JournalFailure)?;
        self.client
            .query_one(
                "SELECT mark_crl_uncertain($1::text::uuid, $2::bigint, $3)",
                &[&plan.reservation.ca_id, &number, &plan.operation_ref],
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
        let number =
            i64::try_from(plan.reservation.crl_number).map_err(|_| CrlError::PersistenceFailure)?;
        self.client
            .query_one(
                "SELECT store_verified_crl($1::text::uuid, $2::bigint, $3, $4, $5, $6)",
                &[
                    &plan.reservation.ca_id,
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
