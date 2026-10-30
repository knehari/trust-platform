-- v0.64 (lab): digests of the migration files applied to this database.
-- LAB ONLY.
-- schema_change_review (0026) records which migrations ran, not what they
-- contained: a migration file edited after it was applied (or a checkout
-- whose history was rewritten) went unnoticed by scripts/lab/migrate.sh.
-- * migration_file_digest: one row per migration file, with the SHA-256 of
--   the file and how it was recorded: 'applied' (the runner applied the
--   file and recorded its digest right after) or 'adopted' (the file had
--   been applied before digests were kept, by the Compose entrypoint or an
--   older runner, and its digest was taken from the checkout at the time:
--   trust on first use). Append-only (ENABLE ALWAYS triggers, as for
--   schema_change_review); owned by trust_schema_audit_owner; no service
--   role reads or writes it.
-- The runner refuses to run when a recorded digest differs from the file
-- in the checkout, or when a recorded file is missing.
-- Apply after 0063 as a superuser.
BEGIN;

CREATE TABLE migration_file_digest (
    migration_ref TEXT PRIMARY KEY CHECK (migration_ref ~ '^[0-9]{4}_[a-z0-9_]+$'),
    file_sha256 BYTEA NOT NULL CHECK (octet_length(file_sha256) = 32),
    recorded_how TEXT NOT NULL CHECK (recorded_how IN ('applied', 'adopted')),
    recorded_by TEXT NOT NULL DEFAULT session_user,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE migration_file_digest OWNER TO trust_schema_audit_owner;
REVOKE ALL ON migration_file_digest FROM PUBLIC;

CREATE TRIGGER migration_file_digest_append_only
    BEFORE UPDATE OR DELETE ON migration_file_digest
    FOR EACH ROW EXECUTE FUNCTION guard_schema_audit();
CREATE TRIGGER migration_file_digest_no_truncate
    BEFORE TRUNCATE ON migration_file_digest
    FOR EACH STATEMENT EXECUTE FUNCTION guard_schema_audit();
ALTER TABLE migration_file_digest ENABLE ALWAYS TRIGGER migration_file_digest_append_only;
ALTER TABLE migration_file_digest ENABLE ALWAYS TRIGGER migration_file_digest_no_truncate;

SELECT acknowledge_schema_changes('0064_migration_file_digest');

COMMIT;
