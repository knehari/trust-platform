-- v0.56 (lab): which CAs carry signed evidence, for the offline audit
-- (ADR-0007 §7, Proposed). LAB ONLY.
-- signed_evidence_audit checked one CA at a time; scheduling it meant
-- listing CAs by hand, and a CA left out was never audited.
-- * evidence_cas(): every CA with a status-change or CA-admin signature or
--   a break-glass use, in id order. Read-only; granted to
--   trust_audit_verifier. `signed_evidence_audit --all` audits each.
-- Apply after 0055 as a superuser.
BEGIN;

CREATE FUNCTION evidence_cas()
RETURNS TABLE (ca_id UUID)
LANGUAGE sql STABLE AS $fn$
    SELECT c.ca_id FROM certificate_status_change c
    WHERE EXISTS (SELECT 1 FROM status_change_signature s WHERE s.change_id = c.change_id)
    UNION
    SELECT ch.ca_id FROM ca_admin_signature s
    JOIN ca_admin_challenge ch USING (challenge_id)
    UNION
    SELECT u.ca_id FROM breakglass_use u
    ORDER BY 1
$fn$;
ALTER FUNCTION evidence_cas() OWNER TO trust_revocation_owner;
ALTER FUNCTION evidence_cas() SECURITY DEFINER;
ALTER FUNCTION evidence_cas() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION evidence_cas() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION evidence_cas() TO trust_audit_verifier;

SELECT acknowledge_schema_changes('0056_evidence_cas');

COMMIT;
