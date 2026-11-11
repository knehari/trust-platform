-- Migration 0044: a dedicated background worker (ADR-0037, Proposed).
--
-- Until now the management API ran the background tasks itself, through its
-- writer login (trust_profile_writer):
-- - sealing committed audit events into the chain (migration 0036);
-- - renewing due CRLs as the system principal
--   urn:trust-platform:system / crl-renewer (migration 0035, 0040).
-- A compromised API process could therefore seal at will, and act as the
-- system renewer, since the renewer's identity was only a pair of
-- parameters any writer could pass.
--
-- From now on a separate worker process does both, with its own login, a
-- member of the new NOLOGIN role trust_worker:
-- - only trust_worker may seal or list renewal candidates; the writer role
--   loses both;
-- - the system principal is accepted by the CRL publication functions only
--   on a session whose login is a direct member of trust_worker, and such a
--   session may act only as the system principal: the worker can never
--   publish as an officer, and the API can never publish as the renewer.
BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_worker') THEN
        CREATE ROLE trust_worker NOLOGIN;
    END IF;
END
$roles$;

-- Whether the login of this session is a direct member of trust_worker.
-- session_user, not current_user: inside a SECURITY DEFINER function
-- current_user is the owner. Direct membership only: a superuser or the owner
-- is not a worker by implication, and SET ROLE does not change session_user.
CREATE FUNCTION session_is_worker() RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog AS $fn$
    SELECT EXISTS (
        SELECT 1 FROM pg_auth_members m
        JOIN pg_roles w ON w.oid = m.roleid AND w.rolname = 'trust_worker'
        JOIN pg_roles s ON s.oid = m.member AND s.rolname = session_user
    )
$fn$;
REVOKE ALL ON FUNCTION session_is_worker() FROM PUBLIC;

-- The system principal only from a worker session, and a worker session
-- only as the system principal. Officers are unchanged.
CREATE OR REPLACE FUNCTION crl_publication_granted(p_issuer TEXT, p_subject TEXT, p_ca UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT CASE
        WHEN session_is_worker() THEN
            p_issuer = 'urn:trust-platform:system'
            AND certificate_role_granted(p_issuer, p_subject, p_ca, 'crl-publisher')
        WHEN p_issuer = 'urn:trust-platform:system' THEN false
        ELSE certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer')
          OR certificate_role_granted(p_issuer, p_subject, p_ca, 'crl-publisher')
    END
$fn$;
REVOKE ALL ON FUNCTION crl_publication_granted(TEXT, TEXT, UUID) FROM PUBLIC;

-- Renewal candidates: the worker only, and only for the system principal.
CREATE OR REPLACE FUNCTION crl_renewal_candidates_lab(p_issuer TEXT, p_subject TEXT)
RETURNS TABLE (ca_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT g.ca_id FROM management_role_grant g
    WHERE session_is_worker() AND p_issuer = 'urn:trust-platform:system'
      AND g.issuer = p_issuer AND g.subject = p_subject AND g.lifecycle_role = 'crl-publisher'
      AND certificate_ca_publishes(g.ca_id) AND crl_renewal_due(g.ca_id)
    ORDER BY g.ca_id
$fn$;
REVOKE ALL ON FUNCTION crl_renewal_candidates_lab(TEXT, TEXT) FROM PUBLIC;
-- CREATE OR REPLACE keeps the old grants: take the writer's away explicitly.
REVOKE EXECUTE ON FUNCTION crl_renewal_candidates_lab(TEXT, TEXT) FROM trust_profile_writer;
GRANT EXECUTE ON FUNCTION crl_renewal_candidates_lab(TEXT, TEXT) TO trust_worker;

-- Sealing: the worker only.
REVOKE EXECUTE ON FUNCTION seal_audit_events_lab(INTEGER) FROM trust_profile_writer;
GRANT EXECUTE ON FUNCTION seal_audit_events_lab(INTEGER) TO trust_worker;

-- The CRL publication path of migration 0031, for the renewer's passes.
GRANT EXECUTE ON FUNCTION begin_crl_publication_lab(TEXT, TEXT, UUID, UUID, BYTEA) TO trust_worker;
GRANT EXECUTE ON FUNCTION crl_publication_entries_lab(TEXT, TEXT, UUID, UUID) TO trust_worker;
GRANT EXECUTE ON FUNCTION record_crl_signing_intent_lab(TEXT, TEXT, UUID, UUID, BYTEA) TO trust_worker;
GRANT EXECUTE ON FUNCTION store_crl_lab(TEXT, TEXT, UUID, UUID, BYTEA) TO trust_worker;
GRANT EXECUTE ON FUNCTION mark_crl_signing_uncertain_lab(TEXT, TEXT, UUID, UUID) TO trust_worker;

CREATE FUNCTION management_dedicated_worker_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_dedicated_worker_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_dedicated_worker_version()
    TO trust_api_reader, trust_profile_writer, trust_worker;

COMMIT;
