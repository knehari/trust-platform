-- Laboratory owner action (ADR-0016, ADR-0019): grants and CRL publication
-- on the lab issuing CA once it
-- has been proposed, attested, approved and activated through the API. Only
-- the database owner holds grants; the API exposes no grant-write route.
-- Usage: psql -v ON_ERROR_STOP=1 -v ca=dddddddd-dddd-4ddd-8ddd-dddddddddddd -f provision-issuing-ca.sql
-- The subjects are the trust-lab realm's fixed user IDs.
\set issuer 'http://127.0.0.1:8080/realms/trust-lab'
BEGIN;
-- psql does not substitute variables inside DO blocks: pass the CA through a
-- transaction-local setting.
SELECT set_config('lab.issuing_ca', :'ca', true) \g /dev/null
DO $check$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM ca_operational_state
                   WHERE ca_id = current_setting('lab.issuing_ca')::uuid AND state = 'ACTIVE') THEN
        RAISE EXCEPTION 'the lab issuing CA is not an ACTIVE lifecycle-managed CA';
    END IF;
END $check$;
INSERT INTO management_reader_grant (issuer, subject, ca_id)
SELECT :'issuer', '7c1a0000-0000-4000-8000-0000000000' || n, :'ca'::uuid
FROM unnest(ARRAY['03', '04', '05', '11', '15', '16', '17']) n
ON CONFLICT DO NOTHING;
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role)
SELECT :'issuer', '7c1a0000-0000-4000-8000-0000000000' || n, :'ca'::uuid, r
FROM (VALUES ('11', 'profile-editor'), ('03', 'policy-approver'), ('04', 'policy-approver'),
             ('05', 'ca-operator'), ('15', 'certificate-requester'), ('16', 'registration-officer'),
             ('17', 'registration-officer')) AS g(n, r)
ON CONFLICT DO NOTHING;
-- Automatic CRL renewal (migration 0035, ADR-0021): the API's renewal task
-- publishes this CA's CRL when it is due.
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role)
VALUES ('urn:trust-platform:system', 'crl-renewer', :'ca'::uuid, 'crl-publisher')
ON CONFLICT DO NOTHING;
-- Public CRL publication (migration 0032, ADR-0019): certificates of this CA
-- name the API's unauthenticated latest-CRL route, on the laboratory's
-- loopback address.
INSERT INTO ca_crl_distribution_point (ca_id, base_url)
VALUES (:'ca'::uuid, 'http://127.0.0.1:8081')
ON CONFLICT DO NOTHING;
COMMIT;
