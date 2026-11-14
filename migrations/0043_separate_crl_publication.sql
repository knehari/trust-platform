-- Migration 0043: CRL publication separated from the management API
-- (ADR-0030, Proposed).
--
-- Until now the management API served the latest CRL of each published CA
-- without authentication (migration 0032). An anonymous, heavily requested
-- endpoint thus shared a process, a database login and an attack surface
-- with every sensitive management operation.
--
-- From now on a separate publisher (`trust-crl-publisher`) reads the latest
-- published CRL of each publishing CA through its own login, verifies it under
-- the CA's registered issuer certificate, and writes it atomically to a
-- static tree. A static HTTP server with no database access serves that tree
-- at the same distribution point path. The API's reader login loses access to
-- the public view; the API no longer serves anything anonymous.
BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_crl_publisher') THEN
        CREATE ROLE trust_crl_publisher NOLOGIN;
    END IF;
END
$roles$;

-- What the publisher reads: the latest published CRL of each CA whose owner
-- configured a distribution point, and the issuer certificate to verify it.
-- Public data only: no names, applications or actors.
CREATE VIEW crl_publisher_feed WITH (security_barrier = true) AS
SELECT d.ca_id::text AS ca_id, d.crl_number, d.crl_der, c.certificate_der AS issuer_certificate_der
FROM crl_document d
JOIN ca_issuer_certificate c ON c.ca_id = d.ca_id
WHERE EXISTS (SELECT 1 FROM ca_crl_distribution_point p WHERE p.ca_id = d.ca_id)
  AND d.crl_number = (SELECT max(l.crl_number) FROM crl_document l WHERE l.ca_id = d.ca_id);
REVOKE ALL ON crl_publisher_feed FROM PUBLIC;
GRANT SELECT ON crl_publisher_feed TO trust_crl_publisher;

-- The API's reader no longer reads the public view (migration 0032).
REVOKE SELECT ON public_crl_latest FROM trust_api_reader;

CREATE FUNCTION management_crl_separate_publication_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_crl_separate_publication_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_crl_separate_publication_version()
    TO trust_api_reader, trust_crl_publisher;

COMMIT;
