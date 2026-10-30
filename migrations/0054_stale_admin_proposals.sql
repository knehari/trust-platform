-- v0.54 (lab): alert on CA-admin proposals past their maximum age
-- (ADR-0006 and ADR-0007, Proposed). LAB ONLY.
-- Since 0052 a proposal older than admin_proposal_max_age_hours can no
-- longer be approved, but it stayed PROPOSED with nobody told to reject it.
-- * stale_admin_proposals(ca): PROPOSED changes of the three families
--   older than the CA's limit (default 168 hours), oldest first. Granted to
--   trust_crl_operator (housekeeping alerts while any remain) and
--   trust_ca_admin.
-- Apply after 0053 as a superuser.
BEGIN;

CREATE FUNCTION stale_admin_proposals(p_ca UUID)
RETURNS TABLE (family TEXT, change_id UUID, proposed_at TIMESTAMPTZ)
LANGUAGE sql STABLE AS $fn$
    WITH lim AS (
        SELECT clock_timestamp() - make_interval(hours => coalesce(
            (SELECT admin_proposal_max_age_hours FROM ca_revocation_policy
             WHERE ca_id = p_ca), 168)) AS before
    )
    SELECT * FROM (
        SELECT 'CA_ADMIN', a.change_id, a.proposed_at FROM ca_admin_change a, lim
        WHERE a.ca_id = p_ca AND a.status = 'PROPOSED' AND a.proposed_at < lim.before
        UNION ALL
        SELECT 'CREDENTIAL', o.change_id, o.proposed_at FROM officer_credential_change o, lim
        WHERE o.ca_id = p_ca AND o.status = 'PROPOSED' AND o.proposed_at < lim.before
        UNION ALL
        SELECT 'ADMIN_CREDENTIAL', k.change_id, k.proposed_at
        FROM ca_admin_credential_change k, lim
        WHERE k.ca_id = p_ca AND k.status = 'PROPOSED' AND k.proposed_at < lim.before
    ) stale
    ORDER BY 3, 2
$fn$;
ALTER FUNCTION stale_admin_proposals(uuid) OWNER TO trust_revocation_owner;
ALTER FUNCTION stale_admin_proposals(uuid) SECURITY DEFINER;
ALTER FUNCTION stale_admin_proposals(uuid) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION stale_admin_proposals(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION stale_admin_proposals(uuid) TO trust_crl_operator, trust_ca_admin;

SELECT acknowledge_schema_changes('0054_stale_admin_proposals');

COMMIT;
