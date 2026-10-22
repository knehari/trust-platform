//! Transactional laboratory runner for management migrations 0012–0016.
//! It deliberately refuses to adopt an existing, untracked management schema.

use postgres::{Client, NoTls, Transaction};
use sha2::{Digest, Sha256};
use std::{env, error::Error, io};

const LOCK_ID: i64 = 0x5452_5553_544d_474d;
const MIGRATIONS: [(&str, &str, &[&str]); 5] = [
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
];

fn main() -> Result<(), Box<dyn Error>> {
    let database_url = env::var("TRUST_MIGRATION_DATABASE_URL")
        .map_err(|_| io::Error::other("set TRUST_MIGRATION_DATABASE_URL for a lab database"))?;
    let mut client = Client::connect(&database_url, NoTls)
        .map_err(|_| io::Error::other("management migration database unavailable"))?;
    client.batch_execute("SET search_path = public")?;
    client.query_one("SELECT pg_advisory_lock($1)", &[&LOCK_ID])?;

    for (version, source, expected_relations) in MIGRATIONS {
        apply_migration(&mut client, version, source, expected_relations)?;
    }
    client.query_one("SELECT pg_advisory_unlock($1)", &[&LOCK_ID])?;
    println!("PASS: management migrations 0012–0016 recorded and current");
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
