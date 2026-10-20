//! Lab-only PostgreSQL integration for the sealed audit chain (migration
//! 0027, ADR-0006 condition 5): the database seals, the Rust verifier
//! re-encodes every record independently, and a superuser's tampering is
//! detected against checkpoints kept outside the database. Tampering runs in
//! transactions that are rolled back, so the shared test database stays
//! intact. Requires TRUST_CI_DATABASE_URL (a superuser login).
#![cfg(feature = "postgres-store")]

use postgres::{Client, NoTls};
use std::env;
use trust_pki_core::{
    audit_chain::{verify_sealed_chain, ChainVerifyError, Checkpoint},
    audit_chain_store::{load_entries, seal, unsealed, AuditChainStoreError},
};

fn database_url() -> Option<String> {
    match env::var("TRUST_CI_DATABASE_URL") {
        Ok(url) => Some(url),
        Err(_) => {
            assert_ne!(
                env::var("TRUST_REQUIRE_DATABASE").as_deref(),
                Ok("1"),
                "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
            );
            None
        }
    }
}

/// `url` with `role` set for the session (the test login is a superuser).
fn url_as(url: &str, role: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-crole%3D{role}")
}

fn sqlstate(error: &AuditChainStoreError) -> Option<String> {
    match error {
        AuditChainStoreError::Database(e) => e.code().map(|c| c.code().to_owned()),
        AuditChainStoreError::Malformed(_) => None,
    }
}

fn insert_event(client: &mut impl postgres::GenericClient, decision: &str) -> String {
    client
        .query_one(
            "INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type,
                                     decision, policy_version)
             VALUES (gen_random_uuid(), NULL, NULL, 'chain-tester', 'audit.chain.probe',
                     $1, NULL)
             RETURNING event_id::text",
            &[&decision],
        )
        .unwrap()
        .get(0)
}

/// The chain the database sealed verifies in Rust (independent encoding of
/// both sources, NULLs and non-ASCII text), with role separation.
#[test]
fn sealed_chain_verifies_outside_the_database() {
    let Some(url) = database_url() else { return };
    let mut owner = Client::connect(&url, NoTls).unwrap();
    insert_event(&mut owner, "accepted: «élevé» ✓");

    let mut sealer = Client::connect(&url_as(&url, "trust_audit_sealer"), NoTls).unwrap();
    let mut verifier = Client::connect(&url_as(&url, "trust_audit_verifier"), NoTls).unwrap();
    while seal(&mut sealer, 1000).unwrap() > 0 {}
    let entries = load_entries(&mut verifier).unwrap();
    assert!(entries.len() >= 2);
    let chain = verify_sealed_chain(entries.clone(), &[]).unwrap();
    let last = entries.last().unwrap();
    assert_eq!(
        (chain.sequence(), chain.head()),
        (last.sequence, last.entry_hash)
    );
    assert_eq!(unsealed(&mut verifier, 0).unwrap(), 0);

    // Each role holds only its own function.
    assert_eq!(
        sqlstate(&seal(&mut verifier, 1).unwrap_err()).as_deref(),
        Some("42501")
    );
    assert_eq!(
        sqlstate(&load_entries(&mut sealer).unwrap_err()).as_deref(),
        Some("42501")
    );
    let mut operator = Client::connect(&url_as(&url, "trust_crl_operator"), NoTls).unwrap();
    assert_eq!(
        sqlstate(&load_entries(&mut operator).unwrap_err()).as_deref(),
        Some("42501")
    );
}

/// A superuser rewrites history; the exported checkpoint catches it.
#[test]
fn tampering_is_detected_against_exported_checkpoints() {
    let Some(url) = database_url() else { return };
    let mut client = Client::connect(&url, NoTls).unwrap();
    let mut tx = client.transaction().unwrap();
    let event = insert_event(&mut tx, "original decision");
    while seal(&mut tx, 1000).unwrap() > 0 {}
    let entries = load_entries(&mut tx).unwrap();
    let head = verify_sealed_chain(entries, &[]).unwrap();
    // Exported outside the database, e.g. by the audit_chain_anchor job.
    let anchor = Checkpoint {
        sequence: head.sequence(),
        head: head.head(),
    };
    let line = anchor.to_line();
    let anchor = Checkpoint::parse_line(&line).unwrap();
    let sealed_at: i64 = tx
        .query_one(
            "SELECT seq FROM audit_chain_entry
             WHERE source = 'audit_event' AND source_key = $1",
            &[&event],
        )
        .unwrap()
        .get(0);
    let sealed_at = sealed_at as u64;
    insert_event(&mut tx, "later decision");
    while seal(&mut tx, 1000).unwrap() > 0 {}

    let mut scenario = |sql: &str| -> ChainVerifyError {
        tx.batch_execute("SAVEPOINT tamper").unwrap();
        tx.batch_execute(sql).unwrap();
        let result = verify_sealed_chain(load_entries(&mut tx).unwrap(), &[anchor]);
        tx.batch_execute("ROLLBACK TO SAVEPOINT tamper").unwrap();
        result.unwrap_err()
    };
    let rewrite_record = format!(
        "ALTER TABLE audit_event DISABLE TRIGGER prevent_audit_update;
         UPDATE audit_event SET decision = 'forged' WHERE event_id = '{event}';"
    );
    // A sealed record rewritten in place.
    assert_eq!(
        scenario(&rewrite_record),
        ChainVerifyError::RecordAltered {
            sequence: sealed_at
        }
    );
    // A sealed record deleted.
    assert_eq!(
        scenario(&format!(
            "ALTER TABLE audit_event DISABLE TRIGGER prevent_audit_update;
             DELETE FROM audit_event WHERE event_id = '{event}';"
        )),
        ChainVerifyError::SourceMissing {
            sequence: sealed_at
        }
    );
    // The chain recomputed after the rewrite: internally consistent, but it
    // no longer matches the exported head.
    assert_eq!(
        scenario(&format!(
            "{rewrite_record}
             ALTER TABLE audit_chain_entry DISABLE TRIGGER audit_chain_entry_append_only;
             DELETE FROM audit_chain_entry WHERE seq >= {sealed_at};
             SELECT seal_audit_chain(100000);"
        )),
        ChainVerifyError::CheckpointMismatch {
            sequence: anchor.sequence
        }
    );
    // The tail cut back below the exported head.
    assert_eq!(
        scenario(&format!(
            "ALTER TABLE audit_chain_entry DISABLE TRIGGER audit_chain_entry_append_only;
             DELETE FROM audit_chain_entry WHERE seq >= {};",
            anchor.sequence
        )),
        ChainVerifyError::Truncated {
            sequence: anchor.sequence
        }
    );
    // Untampered, the extended chain still matches the checkpoint.
    verify_sealed_chain(load_entries(&mut tx).unwrap(), &[anchor]).unwrap();
    tx.rollback().unwrap();
}
