-- v0.26 (lab): schema-change audit (ADR-0006 acceptance condition 3, status
-- Proposed; implemented in lab at the owner's request). LAB ONLY.
-- * Event triggers on ddl_command_end and sql_drop record every DDL command
--   and object GRANT/REVOKE in this database into the append-only
--   schema_change_audit: command tag, object type and identity (PostgreSQL
--   gives only the object type for GRANT/REVOKE), the session user and the
--   transaction id. The session user is the authenticated login; a SET ROLE
--   is not visible because the recorder runs with definer rights. The SQL
--   text is not stored (it may carry credentials). Temporary objects are
--   not recorded.
-- * Both triggers are ENABLE ALWAYS, so session_replication_role = replica
--   does not silence them; the audit tables' guards are ENABLE ALWAYS too.
-- * schema_change_review is the reviewed-migration ledger: a reviewed
--   migration ends with SELECT acknowledge_schema_changes('<ref>'), which
--   marks every change recorded so far as reviewed. It runs with the
--   caller's rights and nobody else holds the tables, so only a superuser
--   can acknowledge.
-- * unreviewed_schema_changes() counts changes after the last review; it is
--   granted to trust_crl_operator and the crl_housekeeping job alerts on it.
-- Not covered (PostgreSQL fires no event trigger for them): roles and role
-- membership, databases, tablespaces, ALTER SYSTEM, and the event triggers
-- themselves. A superuser can drop the triggers or the audit rows; server
-- logging (pgaudit) and an audit trail anchored outside the database
-- (condition 5) cover that.
-- Apply after 0025 as a superuser.
BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_schema_audit_owner') THEN
        CREATE ROLE trust_schema_audit_owner NOLOGIN;
    END IF;
END $roles$;

CREATE TABLE schema_change_audit (
    change_seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    event TEXT NOT NULL CHECK (event IN ('ddl_command_end', 'sql_drop')),
    command_tag TEXT NOT NULL,
    object_type TEXT,
    schema_name TEXT,
    object_identity TEXT,
    session_user_name TEXT NOT NULL,
    transaction_id XID8 NOT NULL
);

CREATE TABLE schema_change_review (
    review_seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    reviewed_up_to BIGINT NOT NULL CHECK (reviewed_up_to >= 0),
    migration_ref TEXT NOT NULL CHECK (migration_ref ~ '^[0-9]{4}[a-z0-9_]*$'),
    reviewed_by TEXT NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE schema_change_audit OWNER TO trust_schema_audit_owner;
ALTER TABLE schema_change_review OWNER TO trust_schema_audit_owner;

CREATE FUNCTION guard_schema_audit()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END $fn$;
ALTER FUNCTION guard_schema_audit() OWNER TO trust_schema_audit_owner;
REVOKE ALL ON FUNCTION guard_schema_audit() FROM PUBLIC;

CREATE TRIGGER schema_change_audit_append_only
    BEFORE UPDATE OR DELETE ON schema_change_audit
    FOR EACH ROW EXECUTE FUNCTION guard_schema_audit();
CREATE TRIGGER schema_change_audit_no_truncate
    BEFORE TRUNCATE ON schema_change_audit
    FOR EACH STATEMENT EXECUTE FUNCTION guard_schema_audit();
CREATE TRIGGER schema_change_review_append_only
    BEFORE UPDATE OR DELETE ON schema_change_review
    FOR EACH ROW EXECUTE FUNCTION guard_schema_audit();
CREATE TRIGGER schema_change_review_no_truncate
    BEFORE TRUNCATE ON schema_change_review
    FOR EACH STATEMENT EXECUTE FUNCTION guard_schema_audit();
ALTER TABLE schema_change_audit ENABLE ALWAYS TRIGGER schema_change_audit_append_only;
ALTER TABLE schema_change_audit ENABLE ALWAYS TRIGGER schema_change_audit_no_truncate;
ALTER TABLE schema_change_review ENABLE ALWAYS TRIGGER schema_change_review_append_only;
ALTER TABLE schema_change_review ENABLE ALWAYS TRIGGER schema_change_review_no_truncate;

-- Definer rights: DDL run by any role is recorded, and no role needs INSERT.
CREATE FUNCTION record_schema_change()
RETURNS EVENT_TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
    IF TG_EVENT = 'sql_drop' THEN
        INSERT INTO public.schema_change_audit (event, command_tag, object_type,
            schema_name, object_identity, session_user_name, transaction_id)
        SELECT TG_EVENT, TG_TAG, d.object_type, d.schema_name, d.object_identity,
               session_user, pg_current_xact_id()
        FROM pg_event_trigger_dropped_objects() d
        WHERE NOT d.is_temporary;
    ELSE
        INSERT INTO public.schema_change_audit (event, command_tag, object_type,
            schema_name, object_identity, session_user_name, transaction_id)
        SELECT TG_EVENT, c.command_tag, c.object_type, c.schema_name,
               c.object_identity, session_user, pg_current_xact_id()
        FROM pg_event_trigger_ddl_commands() c
        WHERE c.schema_name IS DISTINCT FROM 'pg_temp'
          AND coalesce(c.schema_name, '') NOT LIKE 'pg\_temp\_%';
    END IF;
END $fn$;
-- (Re)set explicitly: the definer settings are what make the trigger work
-- for every role (see 0025 on CREATE OR REPLACE).
ALTER FUNCTION record_schema_change() OWNER TO trust_schema_audit_owner;
REVOKE ALL ON FUNCTION record_schema_change() FROM PUBLIC;
GRANT INSERT ON schema_change_audit TO trust_schema_audit_owner;

CREATE EVENT TRIGGER schema_change_audit_ddl ON ddl_command_end
    EXECUTE FUNCTION record_schema_change();
CREATE EVENT TRIGGER schema_change_audit_drop ON sql_drop
    EXECUTE FUNCTION record_schema_change();
ALTER EVENT TRIGGER schema_change_audit_ddl ENABLE ALWAYS;
ALTER EVENT TRIGGER schema_change_audit_drop ENABLE ALWAYS;

-- Invoker rights, granted to nobody: a superuser acknowledges the changes
-- its reviewed migration made.
CREATE FUNCTION acknowledge_schema_changes(p_migration_ref TEXT)
RETURNS BIGINT
LANGUAGE sql
SET search_path = pg_catalog, public, pg_temp AS $fn$
    INSERT INTO public.schema_change_review (reviewed_up_to, migration_ref, reviewed_by)
    SELECT coalesce(max(change_seq), 0), p_migration_ref, session_user
    FROM public.schema_change_audit
    RETURNING reviewed_up_to
$fn$;
REVOKE ALL ON FUNCTION acknowledge_schema_changes(text) FROM PUBLIC;

CREATE FUNCTION unreviewed_schema_changes()
RETURNS BIGINT
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
    SELECT count(*) FROM public.schema_change_audit
    WHERE change_seq > (SELECT coalesce(max(reviewed_up_to), 0)
                        FROM public.schema_change_review)
$fn$;
ALTER FUNCTION unreviewed_schema_changes() OWNER TO trust_schema_audit_owner;
REVOKE ALL ON FUNCTION unreviewed_schema_changes() FROM PUBLIC;
GRANT SELECT ON schema_change_audit, schema_change_review TO trust_schema_audit_owner;
GRANT EXECUTE ON FUNCTION unreviewed_schema_changes() TO trust_crl_operator;

SELECT acknowledge_schema_changes('0026_schema_change_audit');

COMMIT;
