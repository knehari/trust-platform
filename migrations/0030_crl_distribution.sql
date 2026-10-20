-- v0.30 (lab): read-only CRL distribution (RFC 5280 4.2.1.13 / RFC 2585).
-- LAB ONLY. Not a production publication service.
-- * trust_crl_publisher (NOLOGIN, granted to the distribution point's
--   login) can call published_crl only: the highest-numbered STORED CRL of
--   a CA with its times and the CA's registered issuer certificate, so the
--   distribution point re-checks the signature before serving
--   (trust_pki_core::crl::verify_published_crl). No table access, nothing
--   else: a relying party's request can never reach a write path.
-- * Unknown CA or no stored CRL: no row.
-- Apply after 0029 as a superuser.
BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_crl_publisher') THEN
        CREATE ROLE trust_crl_publisher NOLOGIN;
    END IF;
END $roles$;

CREATE FUNCTION published_crl(p_ca UUID)
RETURNS TABLE (crl_number BIGINT, this_update_unix BIGINT, next_update_unix BIGINT,
               crl_der BYTEA, issuer_certificate_der BYTEA)
LANGUAGE sql STABLE AS $fn$
    SELECT p.crl_number, extract(epoch FROM p.this_update)::bigint,
           extract(epoch FROM p.next_update)::bigint, p.crl_der, i.certificate_der
    FROM crl_publication p
    JOIN ca_issuer_certificate i ON i.ca_id = p.ca_id
    WHERE p.ca_id = p_ca AND p.status = 'STORED'
    ORDER BY p.crl_number DESC
    LIMIT 1
$fn$;
ALTER FUNCTION published_crl(uuid) OWNER TO trust_revocation_owner;
ALTER FUNCTION published_crl(uuid) SECURITY DEFINER;
ALTER FUNCTION published_crl(uuid) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION published_crl(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION published_crl(uuid) TO trust_crl_publisher;

SELECT acknowledge_schema_changes('0030_crl_distribution');

COMMIT;
