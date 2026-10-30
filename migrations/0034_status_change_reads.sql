-- v0.34 (lab): what the revocation API may read about status changes.
-- LAB ONLY.
-- * pending_status_changes(ca): the CA's PROPOSED changes (oldest first),
--   with whether the maker signed (0029), so checkers can find work. No
--   evidence, no other status: approvals and history stay in the audit.
-- * status_change_ca(change): the CA of one change, so the API can check the
--   token's CA scope before acting on a change id.
-- Both granted to trust_revocation_officer_api only.
-- Apply after 0033 as a superuser.
BEGIN;

CREATE FUNCTION pending_status_changes(p_ca UUID)
RETURNS TABLE (change_id UUID, serial_der_content BYTEA, action TEXT, reason_code SMALLINT,
               invalidity_at TIMESTAMPTZ, maker_issuer TEXT, maker_subject TEXT,
               proposed_at TIMESTAMPTZ, maker_signed BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT s.change_id, s.serial_der_content, s.action, s.reason_code, s.invalidity_at,
           s.maker_issuer, s.maker_subject, s.proposed_at,
           EXISTS (SELECT 1 FROM status_change_signature g
                   WHERE g.change_id = s.change_id AND g.role = 'MAKER')
    FROM certificate_status_change s
    WHERE s.ca_id = p_ca AND s.status = 'PROPOSED'
    ORDER BY s.proposed_at, s.change_id
    LIMIT 500
$fn$;

CREATE FUNCTION status_change_ca(p_change UUID)
RETURNS UUID
LANGUAGE sql STABLE AS $fn$
    SELECT s.ca_id FROM certificate_status_change s WHERE s.change_id = p_change
$fn$;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY['pending_status_changes(uuid)', 'status_change_ca(uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_revocation_officer_api', f);
    END LOOP;
END $fns$;

SELECT acknowledge_schema_changes('0034_status_change_reads');

COMMIT;
