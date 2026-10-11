//! PostgreSQL adapter integration on the disposable CI database only.
//! Tests durable operations; no cryptographic signing occurs.
#![cfg(feature = "postgres-store")]

use std::env;
use trust_pki_core::postgres_store::{PgIssuanceStore, StoreError};

#[test]
fn persists_request_serial_and_signing_intent_without_resigning() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        // No database is available in ordinary unit-test mode.
        return;
    };
    let mut db = PgIssuanceStore::connect_lab(&url).expect("CI database connection");
    let ca = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    // A dedicated CI issuer is inserted by the schema test job.
    let created = db
        .create_request(ca, "rust-adapter-req-1", &[0x11; 32], "trusted-test-actor", "v1")
        .expect("create request");
    assert_eq!(created.state, "RECEIVED");
    assert!(!created.replay);
    let replay = db
        .create_request(ca, "rust-adapter-req-1", &[0x11; 32], "trusted-test-actor", "v1")
        .expect("idempotent replay");
    assert_eq!(replay.request_id, created.request_id);
    assert!(replay.replay);

    assert_eq!(
        db.transition(ca, &created.request_id, "RECEIVED", "CSR_VALIDATED", "trusted-test-actor")
            .unwrap(),
        "CSR_VALIDATED"
    );
    assert_eq!(
        db.transition(ca, &created.request_id, "CSR_VALIDATED", "AUTHORIZED", "trusted-test-actor")
            .unwrap(),
        "AUTHORIZED"
    );
    let first = db
        .reserve_serial(ca, &created.request_id, "trusted-test-actor")
        .unwrap();
    assert_eq!(first.len(), 16);
    let second = db
        .reserve_serial(ca, &created.request_id, "trusted-test-actor")
        .unwrap();
    assert_eq!(first, second);

    let intent = db
        .record_signing_intent(
            ca,
            &created.request_id,
            "trusted-test-actor",
            "test-only-ephemeral-key",
            &[0x22; 32],
            "v1",
            "rust-test-op-1",
        )
        .unwrap();
    assert_eq!(intent.outcome, "UNCONFIRMED");

    let repeated = db.record_signing_intent(
        ca,
        &created.request_id,
        "trusted-test-actor",
        "test-only-ephemeral-key",
        &[0x22; 32],
        "v1",
        "rust-test-op-1",
    );
    assert!(matches!(repeated, Err(StoreError::ReplayedSigningIntent)));
    assert_eq!(
        db.mark_uncertain(ca, &created.request_id, "trusted-test-actor")
            .unwrap(),
        "RECONCILIATION_REQUIRED"
    );
    assert!(db
        .transition(
            ca,
            &created.request_id,
            "RECONCILIATION_REQUIRED",
            "SIGNING",
            "trusted-test-actor"
        )
        .is_err());
}
