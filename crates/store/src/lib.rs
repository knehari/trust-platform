//! Durable issuance persistence contract (ADR-0002).
//!
//! The PostgreSQL implementation will follow `migrations/0001_init.sql`.
//! [`MemoryStore`] is a reference implementation used to test the ADR-0002
//! invariants independently of a database.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ca_core::issuance::{IssuanceState, TransitionError};
use ca_core::serial::Serial;

pub type IssuerId = String;
pub type IntentId = u64;

/// A signing intent, committed before the provider is called.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub id: IntentId,
    pub issuer: IssuerId,
    pub serial: Serial,
    pub idempotency_key: String,
    pub request_sha256: [u8; 32],
    pub state: IssuanceState,
    /// Set when entering `Signing`: DER TBSCertificate and its SHA-256.
    pub tbs: Option<(Vec<u8>, [u8; 32])>,
    pub certificate: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// `UNIQUE (issuer_id, serial)` violation: serials are never reused.
    SerialAlreadyReserved,
    /// Same idempotency key used with a different request.
    IdempotencyConflict,
    UnknownIntent,
    Transition(TransitionError),
    MissingTbs,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for StoreError {}

impl From<TransitionError> for StoreError {
    fn from(e: TransitionError) -> Self {
        Self::Transition(e)
    }
}

/// Outcome of creating an intent with an idempotency key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reserve {
    New(IntentId),
    /// The same request was already received: return the existing intent.
    Existing(IntentId),
}

/// Persistence operations required by the issuance protocol (ADR-0002).
/// Each method is one database transaction.
pub trait IssuanceStore {
    /// Creates an intent in `SerialReserved` with a fresh serial, or returns the
    /// existing intent for the same `(issuer, idempotency_key)` and request.
    fn reserve(
        &mut self,
        issuer: &str,
        idempotency_key: &str,
        request_sha256: [u8; 32],
        serial: Serial,
    ) -> Result<Reserve, StoreError>;
    /// Commits the TBS and moves to `Signing`. Must succeed before `sign` is called.
    fn begin_signing(&mut self, id: IntentId, tbs_der: Vec<u8>, tbs_sha256: [u8; 32]) -> Result<(), StoreError>;
    /// Stores the verified certificate and moves to `Signed`.
    fn complete_signed(&mut self, id: IntentId, certificate_der: Vec<u8>) -> Result<(), StoreError>;
    /// Moves to another state (failures, reconciliation, voiding, publication).
    fn transition(&mut self, id: IntentId, to: IssuanceState) -> Result<(), StoreError>;
    /// Serials that must appear on the issuer's CRL because a signature may exist
    /// for them but no certificate was recorded (voided after reconciliation).
    fn preventively_revoked(&self, issuer: &str) -> Vec<Serial>;
    fn intent(&self, id: IntentId) -> Option<&Intent>;
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    intents: BTreeMap<IntentId, Intent>,
    serials: BTreeSet<(IssuerId, Vec<u8>)>,
    idempotency: BTreeMap<(IssuerId, String), IntentId>,
    revoked: BTreeMap<IssuerId, Vec<Serial>>,
    next_id: IntentId,
}

impl MemoryStore {
    fn get_mut(&mut self, id: IntentId) -> Result<&mut Intent, StoreError> {
        self.intents.get_mut(&id).ok_or(StoreError::UnknownIntent)
    }
}

impl IssuanceStore for MemoryStore {
    fn reserve(
        &mut self,
        issuer: &str,
        idempotency_key: &str,
        request_sha256: [u8; 32],
        serial: Serial,
    ) -> Result<Reserve, StoreError> {
        let idem = (issuer.to_owned(), idempotency_key.to_owned());
        if let Some(&id) = self.idempotency.get(&idem) {
            let existing = self.intents.get(&id).ok_or(StoreError::UnknownIntent)?;
            return if existing.request_sha256 == request_sha256 {
                Ok(Reserve::Existing(id))
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        if !self.serials.insert((issuer.to_owned(), serial.canonical().to_vec())) {
            return Err(StoreError::SerialAlreadyReserved);
        }
        self.next_id += 1;
        let id = self.next_id;
        self.idempotency.insert(idem, id);
        // The state machine starts at Received; earlier steps (CSR validation,
        // authorization) are recorded by the caller before reservation.
        self.intents.insert(
            id,
            Intent {
                id,
                issuer: issuer.to_owned(),
                serial,
                idempotency_key: idempotency_key.to_owned(),
                request_sha256,
                state: IssuanceState::SerialReserved,
                tbs: None,
                certificate: None,
            },
        );
        Ok(Reserve::New(id))
    }

    fn begin_signing(&mut self, id: IntentId, tbs_der: Vec<u8>, tbs_sha256: [u8; 32]) -> Result<(), StoreError> {
        let intent = self.get_mut(id)?;
        intent.state = intent.state.transition(IssuanceState::Signing)?;
        intent.tbs = Some((tbs_der, tbs_sha256));
        Ok(())
    }

    fn complete_signed(&mut self, id: IntentId, certificate_der: Vec<u8>) -> Result<(), StoreError> {
        let intent = self.get_mut(id)?;
        intent.tbs.as_ref().ok_or(StoreError::MissingTbs)?;
        intent.state = intent.state.transition(IssuanceState::Signed)?;
        intent.certificate = Some(certificate_der);
        Ok(())
    }

    fn transition(&mut self, id: IntentId, to: IssuanceState) -> Result<(), StoreError> {
        let intent = self.get_mut(id)?;
        let from = intent.state;
        intent.state = from.transition(to)?;
        if from == IssuanceState::ReconciliationRequired && to == IssuanceState::Voided {
            let (issuer, serial) = (intent.issuer.clone(), intent.serial.clone());
            self.revoked.entry(issuer).or_default().push(serial);
        }
        Ok(())
    }

    fn preventively_revoked(&self, issuer: &str) -> Vec<Serial> {
        self.revoked.get(issuer).cloned().unwrap_or_default()
    }

    fn intent(&self, id: IntentId) -> Option<&Intent> {
        self.intents.get(&id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use IssuanceState::*;

    fn serial(n: u8) -> Serial {
        Serial::generate_with(|b| {
            b.fill(0);
            if let Some(last) = b.last_mut() {
                *last = n;
            }
            Ok(())
        })
        .unwrap()
    }

    fn new_intent(store: &mut MemoryStore, key: &str, n: u8) -> IntentId {
        match store.reserve("ca-1", key, [n; 32], serial(n)).unwrap() {
            Reserve::New(id) => id,
            Reserve::Existing(_) => panic!("expected new intent"),
        }
    }

    #[test]
    fn serial_is_never_reused_even_after_failure() {
        let mut s = MemoryStore::default();
        let id = new_intent(&mut s, "k1", 1);
        s.begin_signing(id, b"tbs".to_vec(), [0; 32]).unwrap();
        s.transition(id, FailedRetryable).unwrap();
        s.transition(id, Voided).unwrap();
        assert_eq!(s.reserve("ca-1", "k2", [2; 32], serial(1)), Err(StoreError::SerialAlreadyReserved));
        // Same serial under another issuer is allowed.
        assert!(s.reserve("ca-2", "k2", [2; 32], serial(1)).is_ok());
    }

    #[test]
    fn idempotent_replay_returns_existing_and_conflict_is_rejected() {
        let mut s = MemoryStore::default();
        let id = new_intent(&mut s, "k1", 1);
        assert_eq!(s.reserve("ca-1", "k1", [1; 32], serial(9)).unwrap(), Reserve::Existing(id));
        assert_eq!(s.reserve("ca-1", "k1", [7; 32], serial(9)), Err(StoreError::IdempotencyConflict));
    }

    #[test]
    fn crash_during_signing_burns_and_revokes_serial() {
        let mut s = MemoryStore::default();
        let id = new_intent(&mut s, "k1", 3);
        s.begin_signing(id, b"tbs".to_vec(), [0; 32]).unwrap();
        // Indeterminate provider outcome / crash recovery:
        s.transition(id, ReconciliationRequired).unwrap();
        // No persisted certificate found: void, never re-sign.
        assert!(s.transition(id, Signing).is_err());
        s.transition(id, Voided).unwrap();
        assert_eq!(s.preventively_revoked("ca-1"), vec![serial(3)]);
    }

    #[test]
    fn definitive_failure_is_not_revoked() {
        let mut s = MemoryStore::default();
        let id = new_intent(&mut s, "k1", 4);
        s.begin_signing(id, b"tbs".to_vec(), [0; 32]).unwrap();
        s.transition(id, FailedRetryable).unwrap();
        s.transition(id, Voided).unwrap();
        assert!(s.preventively_revoked("ca-1").is_empty());
    }

    #[test]
    fn cannot_sign_without_committed_tbs() {
        let mut s = MemoryStore::default();
        let id = new_intent(&mut s, "k1", 5);
        assert!(s.complete_signed(id, b"cert".to_vec()).is_err());
    }
}
