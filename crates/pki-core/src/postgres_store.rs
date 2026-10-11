//! Synchronous PostgreSQL adapter for **laboratory integration**.
//!
//! AuthenticatedPrincipal, policy approval, TBS provenance and signer identities
//! must be independently established. This module DOES NOT authenticate callers,
//! validate signed certificates, own keys, or invoke an HSM.
//! It may only be used by a future, reviewed least-privilege service boundary.

use postgres::{Client, Error as PgError, NoTls};
use crate::provider_evidence::{EvidenceKind, VerifiedCollectorEvidence};

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

/// Metadata returned by a recovery worker. This is NOT permission to re-sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCandidate {
    pub request_id: String,
    pub intent_id: String,
    pub operation_ref: String,
    pub signer_key_ref: String,
    pub tbs_sha256: [u8; 32],
}

/// Caller-provided references. Production must verify the certificate DER
/// and bind every field to immutable issuer, intent and policy records.
pub struct ReconciliationReviewInput<'a> {
    pub ca_id: &'a str,
    pub request_id: &'a str,
    pub observation_id: &'a str,
    pub maker_actor: &'a str,
    pub operation_ref: &'a str,
    pub tbs_sha256: &'a [u8; 32],
    pub certificate_sha256: &'a [u8; 32],
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

    /// Records only an evidence hash, not evidence authenticity. The actor
    /// identity must be separately authenticated by a reviewed service.
    pub fn record_reconciliation_observation(
        &mut self,
        ca_id: &str,
        request_id: &str,
        actor_id: &str,
        observation_type: &str,
        evidence_sha256: &[u8; 32],
    ) -> Result<String, StoreError> {
        let row = self.client.query_one(
            "SELECT record_signing_reconciliation_observation(
                $1::text::uuid,$2::text::uuid,$3,$4,$5
            )::text",
            &[
                &ca_id,
                &request_id,
                &actor_id,
                &observation_type,
                &&evidence_sha256[..],
            ],
        )?;
        Ok(row.get(0))
    }

    /// This is a review *proposal*, NOT a verified signing result or
    /// a permission to store a recovered certificate.
    pub fn propose_reconciliation_review(
        &mut self,
        input: &ReconciliationReviewInput<'_>,
    ) -> Result<String, StoreError> {
        let row = self.client.query_one(
            "SELECT propose_reconciliation_review(
                $1::text::uuid,$2::text::uuid,$3::text::uuid,$4,$5,$6,$7
            )",
            &[
                &input.ca_id,
                &input.request_id,
                &input.observation_id,
                &input.maker_actor,
                &input.operation_ref,
                &&input.tbs_sha256[..],
                &&input.certificate_sha256[..],
            ],
        )?;
        Ok(row.get(0))
    }

    /// Maker != checker is validated transactionally in PostgreSQL; this
    /// does not authenticate either identity, or resume an issuance.
    pub fn review_reconciliation_proposal(
        &mut self,
        ca_id: &str,
        request_id: &str,
        checker_actor: &str,
        certificate_sha256: &[u8; 32],
        evidence_sha256: &[u8; 32],
    ) -> Result<String, StoreError> {
        let row = self.client.query_one(
            "SELECT review_reconciliation_proposal(
                $1::text::uuid,$2::text::uuid,$3,$4,$5
            )",
            &[
                &ca_id,
                &request_id,
                &checker_actor,
                &&certificate_sha256[..],
                &&evidence_sha256[..],
            ],
        )?;
        Ok(row.get(0))
    }

    /// Persist an already validated collector receipt in PostgreSQL. This
    /// protects against same-event replay and writes a same-transaction audit
    /// event; it cannot authenticate raw vendor/HSM logs or runtime DB actors.
    ///
    /// The returned UUID is an evidence receipt, NOT permission to recover
    /// or publish a certificate and NOT an HSM-provided attestation.
    pub fn persist_verified_collector_evidence(
        &mut self,
        evidence: &VerifiedCollectorEvidence,
    ) -> Result<String, StoreError> {
        let claim = evidence.claim();
        let observed: i64 = claim.observed_at_unix_seconds.try_into()
            .map_err(|_| StoreError::InconsistentResult)?;
        let kind = match claim.kind {
            EvidenceKind::SigningEventObserved => "SIGNING_EVENT",
            EvidenceKind::RetrievedSignedCertificate => "RETRIEVED_CERTIFICATE",
            EvidenceKind::NoMatchingEvent => "NO_MATCHING_EVENT",
        };
        let certificate_digest: Option<&[u8]> =
            claim.certificate_sha256.as_ref().map(|digest| &digest[..]);
        let row = self.client.query_one(
            "SELECT persist_signing_collector_evidence(
                $1::text::uuid,$2::text::uuid,$3,$4,$5,$6,$7,
                $8::bigint,$9,$10,$11,$12,$13,$14
            )::text",
            &[
                &claim.issuer_id,
                &claim.request_id,
                &claim.collector_key_id,
                &claim.audit_event_id,
                &claim.operation_ref,
                &claim.signer_key_ref,
                &claim.policy_revision,
                &observed,
                &kind,
                &&claim.tbs_sha256[..],
                &&claim.raw_provider_log_sha256[..],
                &certificate_digest,
                &evidence.canonical_claim(),
                &evidence.signature_der(),
            ],
        )?;
        Ok(row.get(0))
    }

    /// Fail-closed recovery: scans old UNCONFIRMED signing intents, quarantines
    /// them in PostgreSQL and returns correlation identifiers for investigation.
    /// A returned entry MUST NEVER be fed back to the signer automatically.
    /// min_age_seconds is interpreted by the database clock; CI can use zero.
    pub fn quarantine_stale(
        &mut self,
        ca_id: &str,
        min_age_seconds: i32,
        max_items: i32,
        recovery_actor: &str,
    ) -> Result<Vec<RecoveryCandidate>, StoreError> {
        if min_age_seconds < 0 || !(1..=100).contains(&max_items) {
            return Err(StoreError::InconsistentResult);
        }
        let rows = self.client.query(
            "SELECT request_id::text,intent_id::text,operation_ref,signer_key_ref,tbs_sha256
             FROM quarantine_stale_signing_intents(
                 $1::text::uuid, clock_timestamp() - ($2::int * interval '1 second'),
                 $3::int,$4
             )",
            &[&ca_id, &min_age_seconds, &max_items, &recovery_actor],
        )?;
        rows.into_iter()
            .map(|row| {
                let digest: Vec<u8> = row.get(4);
                let digest: [u8; 32] = digest
                    .try_into()
                    .map_err(|_| StoreError::InconsistentResult)?;
                Ok(RecoveryCandidate {
                    request_id: row.get(0),
                    intent_id: row.get(1),
                    operation_ref: row.get(2),
                    signer_key_ref: row.get(3),
                    tbs_sha256: digest,
                })
            })
            .collect()
    }
}

/// Lab binding of the generic orchestrator to the persistent SQL functions.
/// This does not make the caller a trusted service and MUST NOT be exposed
/// to a network API before authentication, authorization and cert validation.
impl crate::orchestrator::IssuanceJournal for PgIssuanceStore {
    fn record_intent(
        &mut self,
        plan: &crate::orchestrator::IssuancePlan<'_>,
        tbs_sha256: &[u8; 32],
    ) -> Result<(), crate::orchestrator::IssueError> {
        let input = SigningIntentInput {
            ca_id: plan.ca_id,
            request_id: plan.request_id,
            actor_id: plan.actor_id,
            signer_key_ref: plan.signer_key_ref,
            tbs_sha256,
            policy_revision: plan.policy_revision,
            operation_ref: plan.operation_ref,
        };
        self.record_signing_intent(&input)
            .map(|_| ())
            .map_err(|_| crate::orchestrator::IssueError::ReplayedOrAmbiguousIntent)
    }

    fn mark_uncertain(
        &mut self,
        plan: &crate::orchestrator::IssuancePlan<'_>,
    ) -> Result<(), crate::orchestrator::IssueError> {
        self.mark_uncertain(plan.ca_id, plan.request_id, plan.actor_id)
            .map(|_| ())
            .map_err(|_| crate::orchestrator::IssueError::JournalFailure)
    }

    fn persist_verified(
        &mut self,
        plan: &crate::orchestrator::IssuancePlan<'_>,
        tbs_sha256: &[u8; 32],
        certificate_sha256: &[u8; 32],
        certificate_der: &[u8],
    ) -> Result<(), crate::orchestrator::IssueError> {
        let result = self.client.query_one(
            "SELECT store_signed_certificate($1::text::uuid,$2::text::uuid,$3,$4,$5,$6,$7)",
            &[
                &plan.ca_id,
                &plan.request_id,
                &plan.actor_id,
                &plan.serial_der,
                &&tbs_sha256[..],
                &&certificate_sha256[..],
                &certificate_der,
            ],
        );
        match result {
            Ok(row) if row.get::<usize, String>(0) == "SIGNED" => Ok(()),
            _ => Err(crate::orchestrator::IssueError::PersistenceFailure),
        }
    }
}
