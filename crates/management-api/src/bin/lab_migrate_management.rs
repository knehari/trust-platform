//! Transactional laboratory runner for management migrations 0012–0044.
//! It deliberately refuses to adopt an existing, untracked management schema.

use postgres::{Client, Transaction};
use sha2::{Digest, Sha256};
use std::{env, error::Error, io};

const LOCK_ID: i64 = 0x5452_5553_544d_474d;
const MIGRATIONS: [(&str, &str, &[&str]); 33] = [
    (
        "0012_management_read_views",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0012_management_read_views.sql"
        )),
        &[
            "public.management_ca",
            "public.management_certificate",
            "public.management_audit",
        ],
    ),
    (
        "0013_management_reader_grants",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0013_management_reader_grants.sql"
        )),
        &[
            "public.management_reader_grant",
            "public.management_reader_scope",
        ],
    ),
    (
        "0014_certificate_subject_cn",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0014_certificate_subject_cn.sql"
        )),
        &[],
    ),
    (
        "0015_verified_certificate_metadata",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0015_verified_certificate_metadata.sql"
        )),
        &[],
    ),
    (
        "0016_profile_draft_catalogue",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0016_profile_draft_catalogue.sql"
        )),
        &[
            "public.certificate_profile_draft",
            "public.management_profile_draft",
        ],
    ),
    (
        "0017_management_history_window",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0017_management_history_window.sql"
        )),
        &[
            "public.certificate_management_history_window",
            "public.audit_event_management_history_window",
        ],
    ),
    (
        "0018_management_certificate_san",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0018_management_certificate_san.sql"
        )),
        &[
            "public.certificate_san_dns",
            "public.management_certificate_san",
            "public.certificate_san_dns_lookup",
            "public.certificate_management_request_text",
        ],
    ),
    (
        "0019_management_certificate_cn_lower",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0019_management_certificate_cn_lower.sql"
        )),
        &["public.certificate_management_cn_lower"],
    ),
    (
        "0020_management_history_bounds",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0020_management_history_bounds.sql"
        )),
        &[
            "public.certificate_management_ca_signed",
            "public.audit_event_management_ca_recorded",
            "public.management_history_bounds",
        ],
    ),
    (
        "0021_management_reader_isolation",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0021_management_reader_isolation.sql"
        )),
        &[],
    ),
    (
        "0022_profile_draft_submission",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0022_profile_draft_submission.sql"
        )),
        &[
            "public.management_role_grant",
            "public.profile_lifecycle_event",
            "public.certificate_profile_submission",
        ],
    ),
    (
        "0023_profile_draft_decision",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0023_profile_draft_decision.sql"
        )),
        &[
            "public.profile_approver_key",
            "public.certificate_profile_decision",
        ],
    ),
    (
        "0024_profile_revision_activation",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0024_profile_revision_activation.sql"
        )),
        &[
            "public.ca_signing_capability",
            "public.certificate_profile_active",
            "public.certificate_profile_activation",
        ],
    ),
    (
        "0025_profile_draft_revision_sequence",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0025_profile_draft_revision_sequence.sql"
        )),
        &[],
    ),
    (
        "0026_ca_proposal",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0026_ca_proposal.sql"
        )),
        &[
            "public.management_platform_grant",
            "public.ca_lifecycle_event",
            "public.ca_proposal",
            "public.ca_issuer_certificate",
            "public.management_ca_proposal",
        ],
    ),
    (
        "0027_ca_approval_activation",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0027_ca_approval_activation.sql"
        )),
        &[
            "public.ca_approver_key",
            "public.ca_decision",
            "public.ca_activation",
        ],
    ),
    (
        "0028_ca_suspension_retirement",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0028_ca_suspension_retirement.sql"
        )),
        &[
            "public.ca_operational_state",
            "public.ca_state_change",
            "public.ca_change_request",
            "public.ca_change_decision",
            "public.ca_change_application",
        ],
    ),
    (
        "0029_certificate_application",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0029_certificate_application.sql"
        )),
        &[
            "public.certificate_application_event",
            "public.certificate_application",
            "public.certificate_application_decision",
            "public.management_certificate_application",
        ],
    ),
    (
        "0030_application_issuance",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0030_application_issuance.sql"
        )),
        &[
            "public.certificate_application_issuance",
            "public.lab_signer_claim",
            "public.lab_signer_intent",
        ],
    ),
    (
        "0031_revocation_crl",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0031_revocation_crl.sql"
        )),
        &[
            "public.certificate_revocation_request",
            "public.certificate_revocation_decision",
            "public.crl_signing_intent",
            "public.lab_signer_crl_claim",
            "public.crl_document",
            "public.lab_signer_crl_intent",
            "public.lab_signer_crl_entry",
            "public.management_certificate_crl",
        ],
    ),
    (
        "0032_crl_publication",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0032_crl_publication.sql"
        )),
        &[
            "public.ca_crl_distribution_point",
            "public.signing_intent_crl_distribution_point",
            "public.public_crl_latest",
            "public.management_crl_status",
        ],
    ),
    (
        "0033_management_certificate_revocation",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0033_management_certificate_revocation.sql"
        )),
        &["public.management_certificate"],
    ),
    (
        "0034_application_issuance_void",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0034_application_issuance_void.sql"
        )),
        &["public.certificate_application_void"],
    ),
    (
        "0035_crl_auto_renewal",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0035_crl_auto_renewal.sql"
        )),
        &[],
    ),
    (
        "0036_audit_event_chain",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0036_audit_event_chain.sql"
        )),
        &["public.audit_chain_link"],
    ),
    (
        "0037_audit_chain_checkpoint",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0037_audit_chain_checkpoint.sql"
        )),
        &["public.audit_chain_checkpoint"],
    ),
    (
        "0038_ra_issuance_channel",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0038_ra_issuance_channel.sql"
        )),
        &[
            "public.ra_system",
            "public.ra_profile_grant",
            "public.ra_issuance_request",
        ],
    ),
    (
        "0039_ra_revocation_channel",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0039_ra_revocation_channel.sql"
        )),
        &["public.ra_revocation_request"],
    ),
    (
        "0040_crl_publish_on_revocation",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0040_crl_publish_on_revocation.sql"
        )),
        &["public.ca_crl_policy"],
    ),
    (
        "0041_signer_authorization_proofs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0041_signer_authorization_proofs.sql"
        )),
        &[
            "public.registration_officer_key",
            "public.certificate_application_authorization",
            "public.certificate_application_option",
            "public.profile_optional_extension",
        ],
    ),
    (
        "0042_signed_revocation_proofs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0042_signed_revocation_proofs.sql"
        )),
        &[
            "public.crl_entry_proof_policy",
            "public.certificate_revocation_authorization",
            "public.certificate_void_authorization",
        ],
    ),
    (
        "0043_separate_crl_publication",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0043_separate_crl_publication.sql"
        )),
        &["public.crl_publisher_feed"],
    ),
    (
        "0044_dedicated_worker",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/0044_dedicated_worker.sql"
        )),
        &[],
    ),
];

fn main() -> Result<(), Box<dyn Error>> {
    let database_url = env::var("TRUST_MIGRATION_DATABASE_URL")
        .map_err(|_| io::Error::other("set TRUST_MIGRATION_DATABASE_URL for a lab database"))?;
    let mut client = trust_db_connect::connect(&database_url)
        .map_err(|_| io::Error::other("management migration database unavailable"))?;
    client.batch_execute("SET search_path = public")?;
    client.query_one("SELECT pg_advisory_lock($1)", &[&LOCK_ID])?;

    for (version, source, expected_relations) in MIGRATIONS {
        apply_migration(&mut client, version, source, expected_relations)?;
    }
    client.query_one("SELECT pg_advisory_unlock($1)", &[&LOCK_ID])?;
    println!("PASS: management migrations 0012–0044 recorded and current");
    Ok(())
}

fn apply_migration(
    client: &mut Client,
    version: &str,
    source: &str,
    expected_relations: &[&str],
) -> Result<(), Box<dyn Error>> {
    let checksum = format!("{:x}", Sha256::digest(source.as_bytes()));
    let body = migration_body(source)?;
    let mut tx = client.transaction()?;
    let ledger_exists: bool = tx
        .query_one(
            "SELECT to_regclass('public.management_migration_ledger') IS NOT NULL",
            &[],
        )?
        .get(0);
    if !ledger_exists {
        let management_exists: bool = tx
            .query_one(
                "SELECT to_regclass('public.management_ca') IS NOT NULL OR \
                    to_regclass('public.management_certificate') IS NOT NULL OR \
                    to_regclass('public.management_audit') IS NOT NULL OR \
                    to_regclass('public.management_reader_grant') IS NOT NULL OR \
                    to_regclass('public.management_reader_scope') IS NOT NULL OR \
                    to_regclass('public.certificate_profile_draft') IS NOT NULL OR \
                    to_regclass('public.management_profile_draft') IS NOT NULL",
                &[],
            )?
            .get(0);
        if management_exists {
            return Err(
                io::Error::other("untracked management schema; manual adoption required").into(),
            );
        }
        tx.batch_execute(
            "CREATE TABLE management_migration_ledger (\
                version text PRIMARY KEY, \
                source_sha256 text NOT NULL CHECK (length(source_sha256) = 64), \
                applied_at timestamptz NOT NULL DEFAULT now()\
             ); \
             REVOKE ALL ON management_migration_ledger FROM PUBLIC",
        )?;
    }

    if let Some(row) = tx.query_opt(
        "SELECT source_sha256 FROM management_migration_ledger WHERE version = $1",
        &[&version],
    )? {
        let stored: String = row.get(0);
        if stored != checksum {
            return Err(io::Error::other(format!("migration {version} checksum drift")).into());
        }
        if !schema_present(&mut tx, version, expected_relations, true)? {
            return Err(io::Error::other(format!("recorded {version} schema missing")).into());
        }
        println!("SKIP: {version} already recorded with matching checksum");
    } else {
        if !schema_present(&mut tx, version, expected_relations, false)? {
            return Err(io::Error::other(format!(
                "untracked {version} schema; manual adoption required"
            ))
            .into());
        }
        tx.batch_execute(&body)?;
        tx.execute(
            "INSERT INTO management_migration_ledger(version, source_sha256) VALUES ($1, $2)",
            &[&version, &checksum],
        )?;
        println!("APPLY: {version} committed with checksum");
    }
    tx.commit()?;
    Ok(())
}

fn schema_present(
    tx: &mut Transaction<'_>,
    version: &str,
    relations: &[&str],
    require_all: bool,
) -> Result<bool, postgres::Error> {
    if version == "0014_certificate_subject_cn" {
        let row = tx.query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='certificate'::regclass \
             AND attname='subject_cn' AND NOT attisdropped), \
             EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='management_certificate'::regclass \
             AND attname='subject_cn' AND NOT attisdropped), \
             to_regprocedure('store_signed_certificate(uuid,uuid,text,bytea,bytea,bytea,bytea,text)') IS NOT NULL",
            &[],
        )?;
        return Ok((0..3).all(|index| row.get::<usize, bool>(index) == require_all));
    }
    if version == "0015_verified_certificate_metadata" {
        let row = tx.query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='certificate'::regclass \
             AND attname='not_before_utc' AND NOT attisdropped), \
             EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='certificate'::regclass \
             AND attname='not_after_utc' AND NOT attisdropped), \
             EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='certificate'::regclass \
             AND attname='san_dns' AND NOT attisdropped), \
             EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='management_certificate'::regclass \
             AND attname='san_dns' AND NOT attisdropped), \
             to_regprocedure('store_signed_certificate(uuid,uuid,text,bytea,bytea,bytea,bytea,text,text,text,text[])') IS NOT NULL",
            &[],
        )?;
        return Ok((0..5).all(|index| row.get::<usize, bool>(index) == require_all));
    }
    if version == "0016_profile_draft_catalogue" {
        let row = tx.query_one(
            "SELECT to_regprocedure('prevent_profile_draft_change()') IS NOT NULL, \
             EXISTS (SELECT 1 FROM pg_trigger \
                     WHERE tgrelid=to_regclass('public.certificate_profile_draft') \
                       AND tgname='prevent_profile_draft_update' AND NOT tgisinternal)",
            &[],
        )?;
        return Ok(relations_present(tx, relations, require_all)?
            && (0..2).all(|index| row.get::<usize, bool>(index) == require_all));
    }
    if version == "0025_profile_draft_revision_sequence" {
        let row = tx.query_one(
            "SELECT to_regprocedure('enforce_profile_draft_revision_sequence()') IS NOT NULL, \
             EXISTS (SELECT 1 FROM pg_trigger \
                     WHERE tgrelid=to_regclass('public.certificate_profile_draft') \
                       AND tgname='enforce_profile_draft_revision_sequence_after_insert' \
                       AND NOT tgisinternal)",
            &[],
        )?;
        return Ok((0..2).all(|index| row.get::<usize, bool>(index) == require_all));
    }
    if version == "0044_dedicated_worker" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_dedicated_worker_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0043_separate_crl_publication" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_crl_separate_publication_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0042_signed_revocation_proofs" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_revocation_proofs_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0041_signer_authorization_proofs" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_authorization_proofs_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0040_crl_publish_on_revocation" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_crl_on_revocation_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0039_ra_revocation_channel" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_ra_revocation_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0038_ra_issuance_channel" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_ra_channel_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0037_audit_chain_checkpoint" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_audit_checkpoint_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0036_audit_event_chain" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_audit_chain_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0035_crl_auto_renewal" {
        // Functions only; the marker shows whether it ran.
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_crl_renewal_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all);
    }
    if version == "0034_application_issuance_void" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_application_void_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0033_management_certificate_revocation" {
        // The view predates 0033; only the marker shows whether it ran.
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_certificate_revocation_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all);
    }
    if version == "0032_crl_publication" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_crl_publication_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0031_revocation_crl" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_revocation_crl_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0030_application_issuance" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_application_issuance_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0029_certificate_application" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_certificate_application_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0028_ca_suspension_retirement" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_ca_operation_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0027_ca_approval_activation" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_ca_activation_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0026_ca_proposal" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_ca_proposal_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0024_profile_revision_activation" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_profile_activation_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0023_profile_draft_decision" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_profile_decision_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0022_profile_draft_submission" {
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_profile_lifecycle_version()') IS NOT NULL \
                 AND to_regprocedure('create_profile_draft_lab(text,text,uuid,text,text,text,integer,integer,text[],text[],uuid,bytea)') IS NOT NULL \
                 AND to_regprocedure('submit_profile_draft_lab(text,text,uuid,text,integer,bytea,uuid,bytea)') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all && relations_present(tx, relations, require_all)?);
    }
    if version == "0021_management_reader_isolation" {
        // Views are replaced in place; the marker function is the new object.
        let present: bool = tx
            .query_one(
                "SELECT to_regprocedure('management_reader_isolation_version()') IS NOT NULL",
                &[],
            )?
            .get(0);
        return Ok(present == require_all);
    }
    if version == "0019_management_certificate_cn_lower" {
        let row = tx.query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='certificate'::regclass \
             AND attname='subject_cn_lower' AND NOT attisdropped), \
             EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='management_certificate'::regclass \
             AND attname='subject_cn_lower' AND NOT attisdropped)",
            &[],
        )?;
        return Ok(
            (0..2).all(|index| row.get::<usize, bool>(index) == require_all)
                && relations_present(tx, relations, require_all)?,
        );
    }
    if version == "0017_management_history_window" {
        let row = tx.query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='management_certificate'::regclass \
             AND attname='signed_at_window' AND NOT attisdropped), \
             EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='management_audit'::regclass \
             AND attname='recorded_at_window' AND NOT attisdropped)",
            &[],
        )?;
        return Ok(
            (0..2).all(|index| row.get::<usize, bool>(index) == require_all)
                && relations_present(tx, relations, require_all)?,
        );
    }
    relations_present(tx, relations, require_all)
}

fn relations_present(
    tx: &mut Transaction<'_>,
    relations: &[&str],
    require_all: bool,
) -> Result<bool, postgres::Error> {
    for relation in relations {
        let present: bool = tx
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[relation])?
            .get(0);
        if present != require_all {
            return Ok(false);
        }
    }
    Ok(true)
}

fn migration_body(source: &str) -> Result<String, io::Error> {
    let lines: Vec<&str> = source.lines().collect();
    let first = lines
        .iter()
        .position(|line| !line.trim().is_empty() && !line.trim().starts_with("--"))
        .ok_or_else(|| io::Error::other("empty management migration"))?;
    let last = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .ok_or_else(|| io::Error::other("empty management migration"))?;
    if lines[first].trim() != "BEGIN;" || lines[last].trim() != "COMMIT;" || first + 1 >= last {
        return Err(io::Error::other(
            "management migration lacks outer transaction",
        ));
    }
    Ok(lines[first + 1..last].join("\n"))
}
