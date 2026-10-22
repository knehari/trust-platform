-- v0.50 (lab): which CA a pending CA-admin change or a break-glass use
-- belongs to, for the CA-admin API's scope check (ADR-0005, Proposed).
-- LAB ONLY.
-- The API issued approval, rejection and review challenges first and
-- compared the token's CA scope with the issued challenge afterwards, so an
-- out-of-scope request still wrote a challenge row (which since 0049 also
-- counts against the actor's open-challenge cap). The revocation API
-- checks the change's CA before writing; these give the CA-admin API the
-- same order.
-- * admin_change_ca(family, change): the CA of a change in the CA_ADMIN,
--   CREDENTIAL or ADMIN_CREDENTIAL family, NULL if unknown.
-- * breakglass_use_ca(use): the CA of a break-glass use, NULL if unknown.
-- Read-only, granted to trust_ca_admin.
-- Apply after 0049 as a superuser.
BEGIN;

CREATE FUNCTION admin_change_ca(p_family TEXT, p_change UUID)
RETURNS UUID
LANGUAGE sql STABLE AS $fn$
    SELECT CASE p_family
        WHEN 'CA_ADMIN' THEN (SELECT ca_id FROM ca_admin_change WHERE change_id = p_change)
        WHEN 'CREDENTIAL' THEN
            (SELECT ca_id FROM officer_credential_change WHERE change_id = p_change)
        WHEN 'ADMIN_CREDENTIAL' THEN
            (SELECT ca_id FROM ca_admin_credential_change WHERE change_id = p_change)
    END
$fn$;

CREATE FUNCTION breakglass_use_ca(p_use UUID)
RETURNS UUID
LANGUAGE sql STABLE AS $fn$
    SELECT ca_id FROM breakglass_use WHERE use_id = p_use
$fn$;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY['admin_change_ca(text,uuid)', 'breakglass_use_ca(uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_ca_admin', f);
    END LOOP;
END $fns$;

SELECT acknowledge_schema_changes('0050_admin_change_ca_lookup');

COMMIT;
