-- v0.33 (lab): which CAs the CRL housekeeping job covers. LAB ONLY.
-- * crl_issuing_cas() returns the CAs with a registered issuer certificate
--   (0022), i.e. those that can publish CRLs, so one scheduled job checks
--   every one of them instead of a CA list kept by hand (a CA left off the
--   list would silently stop being watched).
-- Granted to trust_crl_operator only; it reveals CA identifiers only.
-- Apply after 0032 as a superuser.
BEGIN;

CREATE FUNCTION crl_issuing_cas()
RETURNS TABLE (ca_id UUID)
LANGUAGE sql STABLE AS $fn$
    SELECT i.ca_id FROM ca_issuer_certificate i ORDER BY i.ca_id
$fn$;
ALTER FUNCTION crl_issuing_cas() OWNER TO trust_revocation_owner;
ALTER FUNCTION crl_issuing_cas() SECURITY DEFINER;
ALTER FUNCTION crl_issuing_cas() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION crl_issuing_cas() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crl_issuing_cas() TO trust_crl_operator;

SELECT acknowledge_schema_changes('0033_crl_operator_ca_list');

COMMIT;
