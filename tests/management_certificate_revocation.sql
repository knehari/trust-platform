-- Migration 0033: the certificate inventory shows recorded revocations. Run
-- as the migration owner after 0033 on a disposable database; every change is
-- rolled back. Before 0033 the first statement fails.
BEGIN;

SELECT revoked_at, revocation_reason FROM management_certificate LIMIT 0;

-- Two authorities, two certificates each; one certificate of X is revoked
-- (keyCompromise, 1) and one of Y (superseded, 4). P1 is granted X only.
INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('7b7b7b7b-0000-4000-8000-0000000000a1', 'Revocation CA X', 'v1'),
    ('7b7b7b7b-0000-4000-8000-0000000000b2', 'Revocation CA Y', 'v1');
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.revocation.invalid', 'p1', '7b7b7b7b-0000-4000-8000-0000000000a1');
INSERT INTO certificate_request (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state)
SELECT ('7b7b7b7b-0000-4000-8000-00000000000' || n)::uuid, ca, 'revocation-' || n,
       decode(repeat('01', 32), 'hex'), 'revocation-test', 'v1', 'SIGNED'
FROM (VALUES (1, '7b7b7b7b-0000-4000-8000-0000000000a1'::uuid), (2, '7b7b7b7b-0000-4000-8000-0000000000a1'::uuid),
             (3, '7b7b7b7b-0000-4000-8000-0000000000b2'::uuid), (4, '7b7b7b7b-0000-4000-8000-0000000000b2'::uuid)) AS v(n, ca);
INSERT INTO serial_reservation (ca_id, serial_der_content, request_id)
SELECT ca, decode('7b0' || n, 'hex'), ('7b7b7b7b-0000-4000-8000-00000000000' || n)::uuid
FROM (VALUES (1, '7b7b7b7b-0000-4000-8000-0000000000a1'::uuid), (2, '7b7b7b7b-0000-4000-8000-0000000000a1'::uuid),
             (3, '7b7b7b7b-0000-4000-8000-0000000000b2'::uuid), (4, '7b7b7b7b-0000-4000-8000-0000000000b2'::uuid)) AS v(n, ca);
INSERT INTO certificate (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at,
                         subject_cn, not_before_utc, not_after_utc, san_dns)
SELECT ca, decode('7b0' || n, 'hex'), ('7b7b7b7b-0000-4000-8000-00000000000' || n)::uuid,
       decode(repeat('02', 32), 'hex'), decode('3000', 'hex'), '2026-01-01T00:00:00Z',
       'revocation-' || n || '.lab.invalid', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', ARRAY['revocation.lab.invalid']
FROM (VALUES (1, '7b7b7b7b-0000-4000-8000-0000000000a1'::uuid), (2, '7b7b7b7b-0000-4000-8000-0000000000a1'::uuid),
             (3, '7b7b7b7b-0000-4000-8000-0000000000b2'::uuid), (4, '7b7b7b7b-0000-4000-8000-0000000000b2'::uuid)) AS v(n, ca);
INSERT INTO revocation (ca_id, serial_der_content, reason_code, revoked_at, actor_id) VALUES
    ('7b7b7b7b-0000-4000-8000-0000000000a1', decode('7b01', 'hex'), 1, '2026-03-04T05:06:07.089Z', 'revocation-officer'),
    ('7b7b7b7b-0000-4000-8000-0000000000b2', decode('7b03', 'hex'), 4, '2026-03-04T05:06:07Z', 'revocation-officer');

SET LOCAL ROLE trust_api_reader;

DO $test$
DECLARE
    seen text;
BEGIN
    IF management_certificate_revocation_version() <> 1 THEN
        RAISE EXCEPTION 'unexpected revocation view version';
    END IF;
    -- No declared principal: nothing.
    IF EXISTS (SELECT 1 FROM management_certificate WHERE ca_id LIKE '7b7b7b7b-%') THEN
        RAISE EXCEPTION 'certificates visible without a declared principal';
    END IF;

    PERFORM set_config('trust.reader_issuer', 'https://issuer.revocation.invalid', true),
            set_config('trust.reader_subject', 'p1', true);
    SELECT string_agg(serial_hex || '=' || coalesce(revoked_at, '-') || '/' || coalesce(revocation_reason::text, '-'),
                      ' ' ORDER BY serial_hex)
      INTO seen FROM management_certificate WHERE ca_id LIKE '7b7b7b7b-%';
    -- The revoked certificate carries its UTC time and reason; the other is
    -- current; nothing of Y, revoked or not, reaches P1.
    IF seen IS DISTINCT FROM '7b01=2026-03-04T05:06:07.089Z/1 7b02=-/-' THEN
        RAISE EXCEPTION 'principal p1 sees %', seen;
    END IF;
    -- The issuance state is unchanged: revocation is reported beside it.
    IF (SELECT state FROM management_certificate WHERE serial_hex = '7b01') <> 'SIGNED' THEN
        RAISE EXCEPTION 'revocation altered the issuance state';
    END IF;
END
$test$;

-- The reader still cannot read the core revocation table directly.
DO $test$
BEGIN
    PERFORM 1 FROM revocation LIMIT 1;
    RAISE EXCEPTION 'trust_api_reader read the revocation table';
EXCEPTION WHEN insufficient_privilege THEN
    NULL;
END
$test$;

ROLLBACK;
\echo 'PASS: management certificate revocation status (0033)'
