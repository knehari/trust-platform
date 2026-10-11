//! Synchronous PostgreSQL adapter for **laboratory integration**.
//!
//! AuthenticatedPrincipal, policy approval, TBS provenance and signer identities
//! must be independently established. This module DOES NOT authenticate callers,
//! validate signed certificates, own keys, or invoke an HSM.
//! It may only be used by a future, reviewed least-privilege service boundary.

use postgres::{Client, Error as PgError, NoTls};

#[derive(Debug)]
pub enum StoreError {
    Database(PgError),
    InconsistentResult,
    ReplayedSigningIntent,
}

impl From<PgError> for StoreError {
    fn from(value: PgError) -> Self {
        Self::Database(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedRequest {
    pub request_id: String,
    pub state: String,
    pub replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedSigningIntent {
    pub intent_id: String,
    pub operation_ref: String,
    pub outcome: String,
}

/// Request metadata previously verified by a trusted authentication and policy boundary.
pub struct SigningIntentInput<'a> {
    pub ca_id: &'a str,
    pub request_id: &'a str,
    pub actor_id: &'a str,
    pub signer_key_ref: &'a str,
    pub tbs_sha256: &'a [u8; 32],
    pub policy_revision: &'a str,
    pub operation_ref: &'a str,
}

/// A replay is a *reference to a prior attempt*, never authorization to sign again.
pub struct PgIssuanceStore {
    client: Client,
}

impl PgIssuanceStore {
    /// Only connect to a trusted local/managed PostgreSQL endpoint.
    /// The connection string and TLS policy are the deployment's responsibility.
    /// NoTls is suitable ONLY for CI's loopback test database.
    pub fn connect_lab(conn_str: &str) -> Result<Self, StoreError> {
        let client = Client::connect(conn_str, NoTls)?;
        Ok(Self { client })
    }

    pub fn create_request(
        &mut self,
        ca_id: &str,
        idempotency_key: &str,
        csr_sha256: &[u8; 32],
        requester_id: &str,
        policy_version: &str,
    ) -> Result<PersistedRequest, StoreError> {
        let row = self.client.query_one(
            "SELECT request_id::text, state, replay
             FROM create_issuance_request($1::text::uuid,$2,$3,$4,$5)",
            &[
                &ca_id,
                &idempotency_key,
                &&csr_sha256[..],
                &requester_id,
                &policy_version,
            ],
        )?;
        Ok(PersistedRequest {
            request_id: row.get(0),
            state: row.get(1),
            replay: row.get(2),
        })
    }

    pub fn transition(
        &mut self,
        ca_id: &str,
        request_id: &str,
        expected_state: &str,
        next_state: &str,
        actor_id: &str,
    ) -> Result<String, StoreError> {
        let row = self.client.query_one(
            "SELECT transition_issuance_request($1::text::uuid,$2::text::uuid,$3,$4,$5)",
            &[&ca_id, &request_id, &expected_state, &next_state, &actor_id],
        )?;
        Ok(row.get(0))
    }

    pub fn reserve_serial(
        &mut self,
        ca_id: &str,
        request_id: &str,
        actor_id: &str,
    ) -> Result<Vec<u8>, StoreError> {
        let row = self.client.query_one(
            "SELECT reserve_issuance_serial($1::text::uuid,$2::text::uuid,$3)",
            &[&ca_id, &request_id, &actor_id],
        )?;
        let serial: Vec<u8> = row.get(0);
        if serial.len() != 16 || !(64..128).contains(&serial[0]) {
            return Err(StoreError::InconsistentResult);
        }
        Ok(serial)
    }

    /// The supplied TBS digest and operation reference are already approved
    /// inputs. The DB does not verify certificate profiles or TBS provenance.
    pub fn record_signing_intent(
        &mut self,
        input: &SigningIntentInput<'_>,
    ) -> Result<PersistedSigningIntent, StoreError> {
        let row = self.client.query_one(
            "SELECT intent_id::text, operation_ref, outcome, replay
             FROM create_signing_intent($1::text::uuid,$2::text::uuid,$3,$4,$5,$6,$7)",
            &[
                &input.ca_id,
                &input.request_id,
                &input.actor_id,
                &input.signer_key_ref,
                &&input.tbs_sha256[..],
                &input.policy_revision,
                &input.operation_ref,
            ],
        )?;
        let replay: bool = row.get(3);
        if replay {
            // Fail-closed: even an identical intent must never trigger
            // a second signing operation after an ambiguous outcome.
            return Err(StoreError::ReplayedSigningIntent);
        }
        Ok(PersistedSigningIntent {
            intent_id: row.get(0),
            operation_ref: row.get(1),
            outcome: row.get(2),
        })
    }

    pub fn mark_uncertain(
        &mut self,
        ca_id: &str,
        request_id: &str,
        actor_id: &str,
    ) -> Result<String, StoreError> {
        let row = self.client.query_one(
            "SELECT mark_signing_uncertain($1::text::uuid,$2::text::uuid,$3)",
            &[&ca_id, &request_id, &actor_id],
        )?;
        Ok(row.get(0))
    }
}
