//! Lab-only PostgreSQL adapter for the sealed audit chain (migration 0027).
//! It only moves rows: the chain is verified by
//! `audit_chain::verify_sealed_chain`, which re-encodes every record itself
//! and compares the heads with checkpoints kept outside the database.
//! Functions take any `GenericClient`, so a client or a transaction works.

use crate::audit_chain::{parse_uuid, AuditRecord, SealedEntry};
use postgres::{Error as PgError, GenericClient, Row};

#[derive(Debug)]
pub enum AuditChainStoreError {
    Database(PgError),
    /// A row does not have the shape migration 0027 defines.
    Malformed(&'static str),
    /// The login is a superuser, can create roles, bypasses row security or
    /// is a member of an owner role: a sealer or verifier that could also
    /// rewrite the records is not one.
    PrivilegedSession,
}

impl From<PgError> for AuditChainStoreError {
    fn from(value: PgError) -> Self {
        Self::Database(value)
    }
}

const PAGE: i32 = 1000;

/// Refuses a privileged session (see `PrivilegedSession`); the audit jobs
/// call it before sealing or verifying.
pub fn refuse_privileged_session(
    client: &mut impl GenericClient,
) -> Result<(), AuditChainStoreError> {
    let privileged: bool = client
        .query_one(
            "SELECT r.rolsuper OR r.rolcreaterole OR r.rolbypassrls
                    OR EXISTS (SELECT 1 FROM pg_roles o
                               WHERE o.rolname IN ('trust_audit_owner', 'trust_revocation_owner')
                                 AND pg_has_role(session_user, o.oid, 'MEMBER'))
             FROM pg_roles r WHERE r.rolname = session_user",
            &[],
        )?
        .try_get(0)?;
    if privileged {
        return Err(AuditChainStoreError::PrivilegedSession);
    }
    Ok(())
}

/// Seal up to `limit` unsealed records (role `trust_audit_sealer`).
pub fn seal(client: &mut impl GenericClient, limit: i32) -> Result<i32, AuditChainStoreError> {
    Ok(client
        .query_one("SELECT seal_audit_chain($1)", &[&limit])?
        .try_get(0)?)
}

/// Records older than `older_than_seconds` not yet sealed (role
/// `trust_audit_verifier`); they are not protected by the chain.
pub fn unsealed(
    client: &mut impl GenericClient,
    older_than_seconds: i64,
) -> Result<i64, AuditChainStoreError> {
    Ok(client
        .query_one(
            "SELECT unsealed_audit_records(make_interval(secs => $1::bigint::float8))",
            &[&older_than_seconds],
        )?
        .try_get(0)?)
}

/// Every sealed entry in sequence order (role `trust_audit_verifier`).
pub fn load_entries(
    client: &mut impl GenericClient,
) -> Result<Vec<SealedEntry>, AuditChainStoreError> {
    let mut entries = Vec::new();
    let mut after = 0i64;
    loop {
        let rows = client.query(
            "SELECT * FROM audit_chain_entries($1, $2)",
            &[&after, &PAGE],
        )?;
        for row in &rows {
            entries.push(entry(row)?);
        }
        match entries.last() {
            Some(last) if rows.len() == PAGE as usize => after = last.sequence as i64,
            _ => return Ok(entries),
        }
    }
}

fn hash(row: &Row, name: &str) -> Result<[u8; 32], AuditChainStoreError> {
    let bytes: Vec<u8> = row.try_get(name)?;
    bytes
        .try_into()
        .map_err(|_| AuditChainStoreError::Malformed("hash is not 32 bytes"))
}

fn uuid(row: &Row, name: &str) -> Result<Option<[u8; 16]>, AuditChainStoreError> {
    let text: Option<String> = row.try_get(name)?;
    text.map(|t| parse_uuid(&t).ok_or(AuditChainStoreError::Malformed("uuid")))
        .transpose()
}

fn required<T>(value: Option<T>) -> Result<T, AuditChainStoreError> {
    value.ok_or(AuditChainStoreError::Malformed("missing column"))
}

fn entry(row: &Row) -> Result<SealedEntry, AuditChainStoreError> {
    let sequence: i64 = row.try_get("seq")?;
    let source: String = row.try_get("source")?;
    let present: bool = row.try_get("source_present")?;
    let record = if !present {
        None
    } else if source == "audit_event" {
        Some(AuditRecord::Event {
            event_id: required(uuid(row, "event_id")?)?,
            ca_id: uuid(row, "ca_id")?,
            request_id: uuid(row, "request_id")?,
            actor_id: required(row.try_get("actor_id")?)?,
            event_type: required(row.try_get("event_type")?)?,
            decision: required(row.try_get("decision")?)?,
            policy_version: row.try_get("policy_version")?,
            recorded_at_us: required(row.try_get("recorded_at_us")?)?,
        })
    } else if source == "schema_change_audit" {
        let transaction_id: String = required(row.try_get("transaction_id")?)?;
        Some(AuditRecord::SchemaChange {
            change_seq: required(row.try_get("change_seq")?)?,
            recorded_at_us: required(row.try_get("recorded_at_us")?)?,
            event: required(row.try_get("change_event")?)?,
            command_tag: required(row.try_get("command_tag")?)?,
            object_type: row.try_get("object_type")?,
            schema_name: row.try_get("schema_name")?,
            object_identity: row.try_get("object_identity")?,
            session_user_name: required(row.try_get("session_user_name")?)?,
            transaction_id: transaction_id
                .parse()
                .map_err(|_| AuditChainStoreError::Malformed("transaction id"))?,
        })
    } else {
        return Err(AuditChainStoreError::Malformed("unknown source"));
    };
    Ok(SealedEntry {
        sequence: u64::try_from(sequence)
            .map_err(|_| AuditChainStoreError::Malformed("negative sequence"))?,
        previous: hash(row, "previous")?,
        event_sha256: hash(row, "event_sha256")?,
        entry_hash: hash(row, "entry_hash")?,
        record,
    })
}
