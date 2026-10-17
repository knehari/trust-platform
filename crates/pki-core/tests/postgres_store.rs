//! PostgreSQL adapter integration on the disposable CI database only.
//! Tests durable operations; no cryptographic signing occurs.
#![cfg(feature = "postgres-store")]

use std::env;
use trust_pki_core::postgres_store::{PgIssuanceStore, SigningIntentInput, StoreError};

#[test]
fn persists_request_serial_and_signing_intent_without_resigning() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        // No database is available in ordinary unit-test mode.
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let mut db = PgIssuanceStore::connect_lab(&url).expect("CI database connection");
    let ca = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    // A dedicated CI issuer is inserted by the schema test job.
    let created = db
        .create_request(
            ca,
            "rust-adapter-req-1",
            &[0x11; 32],
            "trusted-test-actor",
            "v1",
        )
        .expect("create request");
    assert_eq!(created.state, "RECEIVED");
    assert!(!created.replay);
    let replay = db
        .create_request(
            ca,
            "rust-adapter-req-1",
            &[0x11; 32],
            "trusted-test-actor",
            "v1",
        )
        .expect("idempotent replay");
    assert_eq!(replay.request_id, created.request_id);
    assert!(replay.replay);

    assert_eq!(
        db.transition(
            ca,
            &created.request_id,
            "RECEIVED",
            "CSR_VALIDATED",
            "trusted-test-actor"
        )
        .unwrap(),
        "CSR_VALIDATED"
    );
    assert_eq!(
        db.transition(
            ca,
            &created.request_id,
            "CSR_VALIDATED",
            "AUTHORIZED",
            "trusted-test-actor"
        )
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

    let input = SigningIntentInput {
        ca_id: ca,
        request_id: &created.request_id,
        actor_id: "trusted-test-actor",
        signer_key_ref: "test-only-ephemeral-key",
        tbs_sha256: &[0x22; 32],
        policy_revision: "v1",
        operation_ref: "rust-test-op-1",
    };
    let intent = db.record_signing_intent(&input).unwrap();
    assert_eq!(intent.outcome, "UNCONFIRMED");
    let repeated = db.record_signing_intent(&input);
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

#[test]
fn persisted_orchestration_is_fail_closed_after_signer_timeout() {
    use trust_pki_core::orchestrator::{
        issue_once, CertificateAssembler, CertificateVerifier, ExternalSigner, IssuancePlan,
        IssueError,
    };

    struct TimeoutSigner(u32);
    impl ExternalSigner for TimeoutSigner {
        fn sign_once(
            &mut self,
            _key: &str,
            _operation: &str,
            _tbs: &[u8],
        ) -> Result<Vec<u8>, IssueError> {
            self.0 += 1;
            Err(IssueError::SigningFailure)
        }
    }

    struct UnreachableAssembler;
    impl CertificateAssembler for UnreachableAssembler {
        fn assemble(&self, _tbs: &[u8], _signature: &[u8]) -> Result<Vec<u8>, IssueError> {
            panic!("must not assemble after signer timeout")
        }
    }

    struct UnreachableVerifier;
    impl CertificateVerifier for UnreachableVerifier {
        fn verify(
            &self,
            _plan: &IssuancePlan<'_>,
            _certificate_der: &[u8],
        ) -> Result<(), IssueError> {
            panic!("must not verify after signer timeout")
        }
    }

    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let mut db = PgIssuanceStore::connect_lab(&url).unwrap();
    let ca = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let created = db
        .create_request(ca, "orchestrator-timeout", &[0x31; 32], "lab-actor", "v1")
        .unwrap();
    db.transition(
        ca,
        &created.request_id,
        "RECEIVED",
        "CSR_VALIDATED",
        "lab-actor",
    )
    .unwrap();
    db.transition(
        ca,
        &created.request_id,
        "CSR_VALIDATED",
        "AUTHORIZED",
        "lab-actor",
    )
    .unwrap();
    let serial = db
        .reserve_serial(ca, &created.request_id, "lab-actor")
        .unwrap();
    let plan = IssuancePlan {
        ca_id: ca,
        request_id: &created.request_id,
        actor_id: "lab-actor",
        signer_key_ref: "lab-signer",
        policy_revision: "v1",
        operation_ref: "lab-timeout-op",
        serial_der: &serial,
        tbs_der: b"test-TBS-not-real-x509",
    };
    let mut signer = TimeoutSigner(0);
    assert_eq!(
        issue_once(
            &mut db,
            &mut signer,
            &UnreachableAssembler,
            &UnreachableVerifier,
            &plan
        ),
        Err(IssueError::SigningFailure)
    );
    assert_eq!(signer.0, 1);
    assert_eq!(
        issue_once(
            &mut db,
            &mut signer,
            &UnreachableAssembler,
            &UnreachableVerifier,
            &plan
        ),
        Err(IssueError::ReplayedOrAmbiguousIntent)
    );
    assert_eq!(signer.0, 1);
    assert_eq!(
        db.mark_uncertain(ca, &created.request_id, "lab-actor")
            .unwrap(),
        "RECONCILIATION_REQUIRED"
    );
}

#[test]
fn review_workflow_requires_two_actors_and_never_resumes_signing() {
    use trust_pki_core::postgres_store::ReconciliationReviewInput;

    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let mut store = PgIssuanceStore::connect_lab(&url).unwrap();
    let ca = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let actor = "rust-maker-v09";
    let request = store
        .create_request(ca, "rust-v09-review", &[0x51; 32], actor, "v1")
        .unwrap();
    store
        .transition(ca, &request.request_id, "RECEIVED", "CSR_VALIDATED", actor)
        .unwrap();
    store
        .transition(
            ca,
            &request.request_id,
            "CSR_VALIDATED",
            "AUTHORIZED",
            actor,
        )
        .unwrap();
    store
        .reserve_serial(ca, &request.request_id, actor)
        .unwrap();
    store
        .record_signing_intent(&SigningIntentInput {
            ca_id: ca,
            request_id: &request.request_id,
            actor_id: actor,
            signer_key_ref: "lab-key-v09",
            tbs_sha256: &[0x33; 32],
            policy_revision: "v1",
            operation_ref: "lab-op-v09",
        })
        .unwrap();
    store
        .mark_uncertain(ca, &request.request_id, actor)
        .unwrap();
    let observation_id = store
        .record_reconciliation_observation(
            ca,
            &request.request_id,
            actor,
            "PROVIDER_RESULT_OBSERVED",
            &[0x44; 32],
        )
        .unwrap();

    let input = ReconciliationReviewInput {
        ca_id: ca,
        request_id: &request.request_id,
        observation_id: &observation_id,
        maker_actor: actor,
        operation_ref: "lab-op-v09",
        tbs_sha256: &[0x33; 32],
        certificate_sha256: &[0x55; 32],
    };
    assert_eq!(
        store.propose_reconciliation_review(&input).unwrap(),
        "PROPOSED"
    );
    assert!(store
        .review_reconciliation_proposal(ca, &request.request_id, actor, &[0x55; 32], &[0x44; 32])
        .is_err());
    assert!(store
        .review_reconciliation_proposal(
            ca,
            &request.request_id,
            "checker",
            &[0x66; 32],
            &[0x44; 32]
        )
        .is_err());
    assert_eq!(
        store
            .review_reconciliation_proposal(
                ca,
                &request.request_id,
                "independent-checker",
                &[0x55; 32],
                &[0x44; 32]
            )
            .unwrap(),
        "REVIEWED_FOR_MANUAL_DISPOSITION"
    );
    let mut other = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let row = other
        .query_one(
            "SELECT state,(SELECT count(*) FROM certificate WHERE request_id=$1::text::uuid)
         FROM certificate_request WHERE request_id=$1::text::uuid",
            &[&request.request_id],
        )
        .unwrap();
    let state: String = row.get(0);
    let certificates: i64 = row.get(1);
    assert_eq!(state, "RECONCILIATION_REQUIRED");
    assert_eq!(certificates, 0);
}
