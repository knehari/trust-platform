-- Migration 0040: publish a CRL as soon as a revocation is recorded, per CA,
-- in the laboratory (ADR-0027, Proposed; extends ADR-0021).
--
-- Until now a CRL was renewed only when due by time: none yet, or nextUpdate
-- within two days. A revocation then waited up to the CRL's lifetime before
-- relying parties could see it.
--
-- The database owner now sets, per CA, `publish_on_revocation`. When it is
-- on, a CRL is also due when a revocation or a voided serial (migration 0034)
-- is not yet listed on the latest published CRL. That means its instant is
-- after that CRL intent's `entries_until`. The API requests a renewal pass
-- right after it records a revocation; the periodic pass catches anything
-- missed. The renewer of migration 0035 publishes through the unchanged
-- journaled path, and only for the CAs granted to it. The setting changes
-- nothing for a CA where it is off.
BEGIN;

CREATE TABLE ca_crl_policy (
    ca_id UUID PRIMARY KEY REFERENCES ca (ca_id),
    publish_on_revocation BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_crl_policy FROM PUBLIC;

-- Revocations and voided serials of the CA not yet on its latest published
-- CRL: all of them when none was published.
CREATE FUNCTION crl_unpublished_entries(p_ca UUID) RETURNS BIGINT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    WITH latest AS (
        SELECT i.entries_until
        FROM crl_document d JOIN crl_signing_intent i ON i.intent_id = d.intent_id
        WHERE d.ca_id = p_ca ORDER BY d.crl_number DESC LIMIT 1
    )
    SELECT (SELECT count(*) FROM revocation r
            WHERE r.ca_id = p_ca
              AND r.revoked_at > coalesce((SELECT entries_until FROM latest), '-infinity'))
         + (SELECT count(*) FROM certificate_application_void v
            WHERE v.ca_id = p_ca AND v.voided_at IS NOT NULL
              AND v.voided_at > coalesce((SELECT entries_until FROM latest), '-infinity'))
$fn$;
REVOKE ALL ON FUNCTION crl_unpublished_entries(UUID) FROM PUBLIC;

-- Due by time (migration 0035), or, when the CA publishes on revocation,
-- because an entry is not yet on the latest published CRL.
CREATE OR REPLACE FUNCTION crl_renewal_due(p_ca UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT coalesce((SELECT i.next_update <= now() + interval '2 days'
                     FROM crl_document d JOIN crl_signing_intent i ON i.intent_id = d.intent_id
                     WHERE d.ca_id = p_ca ORDER BY d.crl_number DESC LIMIT 1), true)
        OR (coalesce((SELECT p.publish_on_revocation FROM ca_crl_policy p WHERE p.ca_id = p_ca), false)
            AND crl_unpublished_entries(p_ca) > 0)
$fn$;

-- Readers see the setting and how many entries wait for the next CRL.
CREATE OR REPLACE VIEW management_crl_status WITH (security_barrier = true) AS
SELECT c.ca_id::text AS ca_id,
       CASE WHEN p.ca_id IS NOT NULL
            THEN p.base_url || '/v1/public/crls/' || c.ca_id::text || '/latest.crl' END AS distribution_point,
       latest.crl_number AS latest_crl_number,
       to_char(latest.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS next_update,
       latest.crl_number IS NULL OR latest.next_update <= now() + interval '2 days' AS renewal_due,
       latest.crl_number IS NOT NULL AND latest.next_update <= now() AS expired,
       EXISTS (SELECT 1 FROM management_role_grant r
               WHERE r.ca_id = c.ca_id AND r.issuer = 'urn:trust-platform:system'
                 AND r.subject = 'crl-renewer' AND r.lifecycle_role = 'crl-publisher') AS auto_renewal,
       coalesce((SELECT o.publish_on_revocation FROM ca_crl_policy o WHERE o.ca_id = c.ca_id), false)
           AS publish_on_revocation,
       -- crl_unpublished_entries, inlined: a view runs functions with the
       -- reader's privileges, and readers may not call it for any CA.
       (SELECT count(*) FROM revocation r
        WHERE r.ca_id = c.ca_id AND r.revoked_at > coalesce(latest.entries_until, '-infinity'))
       + (SELECT count(*) FROM certificate_application_void v
          WHERE v.ca_id = c.ca_id AND v.voided_at IS NOT NULL
            AND v.voided_at > coalesce(latest.entries_until, '-infinity')) AS unpublished_entries
FROM ca_activation c
LEFT JOIN ca_crl_distribution_point p ON p.ca_id = c.ca_id
LEFT JOIN LATERAL (
    SELECT d.crl_number, i.next_update, i.entries_until
    FROM crl_document d JOIN crl_signing_intent i ON i.intent_id = d.intent_id
    WHERE d.ca_id = c.ca_id ORDER BY d.crl_number DESC LIMIT 1
) latest ON true
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = c.ca_id
);

CREATE FUNCTION management_crl_on_revocation_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_crl_on_revocation_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_crl_on_revocation_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
