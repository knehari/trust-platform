-- v0.57 (lab): review of role changes (ADR-0006 condition 3, Proposed).
-- LAB ONLY.
-- The 0026 event triggers record DDL and object grants, but not role
-- changes: CREATE/ALTER/DROP ROLE and GRANT/REVOKE of a role are global
-- objects and fire no event trigger. A new login granted trust_ca_admin,
-- or a role given SUPERUSER, went unnoticed.
-- * role_state(): the security-relevant role state as sorted text lines:
--   every non-pg_ role that is a trust_* role, a member of one, or holds
--   SUPERUSER, CREATEROLE, BYPASSRLS or REPLICATION (with its LOGIN,
--   INHERIT and those attributes), and every membership into or out of a
--   trust_* role (with its admin option).
-- * role_state_review: append-only snapshots acknowledged by a superuser
--   (acknowledge_role_state(ref), no grant), like schema_change_review.
-- * unreviewed_role_changes(): how many lines differ from the last
--   acknowledged snapshot (added plus removed); granted to
--   trust_crl_operator, reported by crl_housekeeping (attention status).
-- This detects changes at the next housekeeping pass; it does not prevent
-- them and does not say who made them (server-side logging remains open).
-- Apply after 0056 as a superuser.
BEGIN;

CREATE TABLE role_state_review (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    state TEXT[] NOT NULL,
    migration_ref TEXT NOT NULL CHECK (length(migration_ref) BETWEEN 1 AND 200),
    reviewed_by TEXT NOT NULL DEFAULT session_user,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE role_state_review OWNER TO trust_schema_audit_owner;
REVOKE ALL ON role_state_review FROM PUBLIC;

CREATE FUNCTION guard_role_state_review() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'role_state_review is append-only' USING ERRCODE = '23514';
END $fn$;
ALTER FUNCTION guard_role_state_review() OWNER TO trust_schema_audit_owner;
ALTER FUNCTION guard_role_state_review() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION guard_role_state_review() FROM PUBLIC;
CREATE TRIGGER role_state_review_append_only
    BEFORE UPDATE OR DELETE ON role_state_review
    FOR EACH ROW EXECUTE FUNCTION guard_role_state_review();
CREATE TRIGGER role_state_review_no_truncate
    BEFORE TRUNCATE ON role_state_review
    FOR EACH STATEMENT EXECUTE FUNCTION guard_role_state_review();

CREATE FUNCTION role_state()
RETURNS TEXT[]
LANGUAGE sql STABLE AS $fn$
    WITH trust AS (
        SELECT oid FROM pg_roles WHERE rolname LIKE 'trust\_%'
    ),
    relevant AS (
        SELECT r.* FROM pg_roles r
        WHERE r.rolname NOT LIKE 'pg\_%'
          AND (r.oid IN (SELECT oid FROM trust)
               OR r.rolsuper OR r.rolcreaterole OR r.rolbypassrls OR r.rolreplication
               OR EXISTS (SELECT 1 FROM pg_auth_members m
                          WHERE m.member = r.oid AND m.roleid IN (SELECT oid FROM trust)))
    ),
    lines AS (
        SELECT format('role %s login=%s inherit=%s super=%s createrole=%s bypassrls=%s replication=%s',
                      rolname, rolcanlogin, rolinherit, rolsuper, rolcreaterole, rolbypassrls,
                      rolreplication) AS line
        FROM relevant
        UNION ALL
        SELECT format('member %s of %s admin=%s', mr.rolname, gr.rolname, m.admin_option)
        FROM pg_auth_members m
        JOIN pg_roles gr ON gr.oid = m.roleid
        JOIN pg_roles mr ON mr.oid = m.member
        WHERE gr.oid IN (SELECT oid FROM trust) OR mr.oid IN (SELECT oid FROM trust)
    )
    SELECT coalesce(array_agg(line ORDER BY line), ARRAY[]::text[]) FROM lines
$fn$;
ALTER FUNCTION role_state() OWNER TO trust_schema_audit_owner;
ALTER FUNCTION role_state() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION role_state() FROM PUBLIC;

-- Superuser only (no grant), like acknowledge_schema_changes.
CREATE FUNCTION acknowledge_role_state(p_migration_ref TEXT)
RETURNS INTEGER
LANGUAGE sql
SET search_path = pg_catalog, public, pg_temp AS $fn$
    INSERT INTO public.role_state_review (state, migration_ref)
    SELECT public.role_state(), p_migration_ref
    RETURNING cardinality(state)
$fn$;
REVOKE ALL ON FUNCTION acknowledge_role_state(text) FROM PUBLIC;

CREATE FUNCTION unreviewed_role_changes()
RETURNS BIGINT
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
    WITH reviewed AS (
        SELECT unnest(coalesce((SELECT state FROM public.role_state_review
                                ORDER BY review_id DESC LIMIT 1), ARRAY[]::text[])) AS line
    ),
    current_state AS (SELECT unnest(public.role_state()) AS line)
    SELECT (SELECT count(*) FROM (SELECT line FROM current_state
                                  EXCEPT SELECT line FROM reviewed) added)
         + (SELECT count(*) FROM (SELECT line FROM reviewed
                                  EXCEPT SELECT line FROM current_state) removed)
$fn$;
ALTER FUNCTION unreviewed_role_changes() OWNER TO trust_schema_audit_owner;
REVOKE ALL ON FUNCTION unreviewed_role_changes() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION unreviewed_role_changes() TO trust_crl_operator;

SELECT acknowledge_role_state('0057_role_change_review');
SELECT acknowledge_schema_changes('0057_role_change_review');

COMMIT;
