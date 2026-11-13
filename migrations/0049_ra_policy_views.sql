-- Migration 0049: readers see the RA channel's policies (ADR-0044,
-- Proposed).
--
-- The owner sets, in SQL:
-- - RA systems and their profile grants (0038);
-- - their quotas and zones (0046);
-- - their keys (0047);
-- - short-lived profiles (0048).
-- Nobody else could see them. These views show them, read-only, to the
-- readers of each CA, with the same principal filter as every management
-- view. They show:
-- - each RA granted a profile of the CA: whether it is enabled, its
--   profiles, its effective quotas and their use in the last hour, its
--   zones, and its keys (SHA-256 fingerprints and dates, never more);
-- - the CA's short-lived profiles and their bound.
-- Changing any of it stays the owner's.
BEGIN;

CREATE VIEW management_ra_system WITH (security_barrier = true) AS
SELECT g.ca_id::text AS ca_id, r.ra_id, r.display_name, r.enabled, g.profile_ids,
       -- Inlined (a view's functions run with the reader's privileges):
       -- ra_effective_policy's defaults.
       coalesce(p.max_issuance_per_hour, 100) AS max_issuance_per_hour,
       coalesce(p.max_revocation_per_hour, 20) AS max_revocation_per_hour,
       p.allowed_dns_zones,
       (SELECT count(*) FROM ra_issuance_request q
        WHERE q.ra_id = r.ra_id AND q.recorded_at > clock_timestamp() - interval '1 hour') AS issuance_last_hour,
       (SELECT count(*) FROM ra_revocation_request q
        WHERE q.ra_id = r.ra_id AND q.recorded_at > clock_timestamp() - interval '1 hour') AS revocation_last_hour,
       (SELECT coalesce(jsonb_agg(jsonb_build_object(
                   'key_id', k.key_id,
                   'sha256', encode(digest(k.public_key_sec1, 'sha256'), 'hex'),
                   'activated_at', to_char(k.activated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   'retired_at', to_char(k.retired_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
                   ORDER BY k.key_id), '[]'::jsonb)
        FROM ra_system_key k WHERE k.ra_id = r.ra_id)::text AS keys_json
FROM (SELECT ca_id, ra_id, array_agg(profile_id ORDER BY profile_id) AS profile_ids
      FROM ra_profile_grant GROUP BY ca_id, ra_id) g
JOIN ra_system r ON r.ra_id = g.ra_id
LEFT JOIN ra_system_policy p ON p.ra_id = r.ra_id
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant m
    WHERE m.issuer = current_setting('trust.reader_issuer', true)
      AND m.subject = current_setting('trust.reader_subject', true)
      AND m.ca_id = g.ca_id
);
REVOKE ALL ON management_ra_system FROM PUBLIC;
GRANT SELECT ON management_ra_system TO trust_api_reader;

CREATE VIEW management_short_lived_profile WITH (security_barrier = true) AS
SELECT s.ca_id::text AS ca_id, s.profile_id, s.max_validity_days,
       to_char(s.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at
FROM profile_short_lived_policy s
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant m
    WHERE m.issuer = current_setting('trust.reader_issuer', true)
      AND m.subject = current_setting('trust.reader_subject', true)
      AND m.ca_id = s.ca_id
);
REVOKE ALL ON management_short_lived_profile FROM PUBLIC;
GRANT SELECT ON management_short_lived_profile TO trust_api_reader;

CREATE FUNCTION management_ra_policy_views_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_ra_policy_views_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_ra_policy_views_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
