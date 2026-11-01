-- Migration 0021: every management view returns only the rows of authorities
-- granted to the reader principal the session declares, and nothing without
-- one. Run as the migration owner after 0021 on a disposable database; every
-- change is rolled back. Before 0021 the first check fails: the views
-- returned every authority to any trust_api_reader session.
BEGIN;

-- Two authorities with one certificate, SAN and audit event each; principal
-- P1 is granted X only, P2 is granted Y only.
INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('7a7a7a7a-0000-4000-8000-0000000000a1', 'Isolation CA X', 'v1'),
    ('7a7a7a7a-0000-4000-8000-0000000000b2', 'Isolation CA Y', 'v1');
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.isolation.invalid', 'p1', '7a7a7a7a-0000-4000-8000-0000000000a1'),
    ('https://issuer.isolation.invalid', 'p2', '7a7a7a7a-0000-4000-8000-0000000000b2');
INSERT INTO certificate_request (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state)
SELECT ('7a7a7a7a-0000-4000-8000-00000000000' || n)::uuid, ca, 'isolation-' || n,
       decode(repeat('01', 32), 'hex'), 'isolation-test', 'v1', 'SIGNED'
FROM (VALUES (1, '7a7a7a7a-0000-4000-8000-0000000000a1'::uuid), (2, '7a7a7a7a-0000-4000-8000-0000000000b2'::uuid)) AS v(n, ca);
INSERT INTO serial_reservation (ca_id, serial_der_content, request_id)
SELECT ca, decode('7a0' || n, 'hex'), ('7a7a7a7a-0000-4000-8000-00000000000' || n)::uuid
FROM (VALUES (1, '7a7a7a7a-0000-4000-8000-0000000000a1'::uuid), (2, '7a7a7a7a-0000-4000-8000-0000000000b2'::uuid)) AS v(n, ca);
INSERT INTO certificate (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at,
                         subject_cn, not_before_utc, not_after_utc, san_dns)
SELECT ca, decode('7a0' || n, 'hex'), ('7a7a7a7a-0000-4000-8000-00000000000' || n)::uuid,
       decode(repeat('02', 32), 'hex'), decode('3000', 'hex'), '2026-01-01T00:00:00Z',
       'shared.lab.invalid', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', ARRAY['shared.lab.invalid']
FROM (VALUES (1, '7a7a7a7a-0000-4000-8000-0000000000a1'::uuid), (2, '7a7a7a7a-0000-4000-8000-0000000000b2'::uuid)) AS v(n, ca);
INSERT INTO certificate_profile_draft
    (ca_id, profile_id, revision, display_name, policy_version, max_validity_days, max_dns_sans,
     proposed_dns_zones, proposed_signature_suites, created_by)
SELECT ca, 'isolation-profile', 1, 'Isolation profile', 'v1', 90, 5,
       ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'isolation-editor'
FROM (VALUES ('7a7a7a7a-0000-4000-8000-0000000000a1'::uuid), ('7a7a7a7a-0000-4000-8000-0000000000b2'::uuid)) AS v(ca);
INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version, recorded_at)
SELECT ('7a7a7a7a-0000-4000-8000-0000000000e' || n)::uuid, ca, 'isolation-actor', 'certificate.signed', 'allow', 'v1',
       '2026-01-01T00:00:00Z'
FROM (VALUES (1, '7a7a7a7a-0000-4000-8000-0000000000a1'::uuid), (2, '7a7a7a7a-0000-4000-8000-0000000000b2'::uuid)) AS v(n, ca);

SET LOCAL ROLE trust_api_reader;

-- The CAs each view shows to the session, in one text value.
CREATE TEMP VIEW isolation_seen AS
SELECT concat_ws(' ',
    'ca:' || coalesce((SELECT string_agg(ca_id, ',' ORDER BY ca_id) FROM management_ca
                       WHERE ca_id LIKE '7a7a7a7a-%'), '-'),
    'certificate:' || coalesce((SELECT string_agg(ca_id, ',' ORDER BY ca_id) FROM management_certificate
                                WHERE ca_id LIKE '7a7a7a7a-%'), '-'),
    'audit:' || coalesce((SELECT string_agg(ca_id, ',' ORDER BY ca_id) FROM management_audit
                          WHERE ca_id LIKE '7a7a7a7a-%'), '-'),
    'scope:' || coalesce((SELECT string_agg(ca_id, ',' ORDER BY ca_id) FROM management_reader_scope
                          WHERE ca_id LIKE '7a7a7a7a-%'), '-'),
    'san:' || coalesce((SELECT string_agg(ca_id, ',' ORDER BY ca_id) FROM management_certificate_san
                        WHERE ca_id LIKE '7a7a7a7a-%'), '-'),
    'bounds:' || coalesce((SELECT string_agg(ca_id, ',' ORDER BY ca_id) FROM management_history_bounds
                           WHERE ca_id LIKE '7a7a7a7a-%'), '-'),
    'profile:' || coalesce((SELECT string_agg(ca_id, ',' ORDER BY ca_id) FROM management_profile_draft
                            WHERE ca_id LIKE '7a7a7a7a-%'), '-')) AS seen;

DO $test$
DECLARE
    x text := '7a7a7a7a-0000-4000-8000-0000000000a1';
    y text := '7a7a7a7a-0000-4000-8000-0000000000b2';
    seen text;
    expected text;
BEGIN
    -- No declared principal: nothing, even without any predicate of the caller.
    SELECT i.seen INTO seen FROM isolation_seen i;
    IF seen <> 'ca:- certificate:- audit:- scope:- san:- bounds:- profile:-' THEN
        RAISE EXCEPTION 'views return rows without a declared principal: %', seen;
    END IF;

    -- P1 sees X in every view, and never Y.
    PERFORM set_config('trust.reader_issuer', 'https://issuer.isolation.invalid', true),
            set_config('trust.reader_subject', 'p1', true);
    SELECT i.seen INTO seen FROM isolation_seen i;
    expected := format('ca:%1$s certificate:%1$s audit:%1$s scope:%1$s san:%1$s bounds:%1$s profile:%1$s', x);
    IF seen <> expected THEN
        RAISE EXCEPTION 'principal p1 sees %, expected %', seen, expected;
    END IF;

    -- P2 sees Y only.
    PERFORM set_config('trust.reader_subject', 'p2', true);
    SELECT i.seen INTO seen FROM isolation_seen i;
    expected := format('ca:%1$s certificate:%1$s audit:%1$s scope:%1$s san:%1$s bounds:%1$s profile:%1$s', y);
    IF seen <> expected THEN
        RAISE EXCEPTION 'principal p2 sees %, expected %', seen, expected;
    END IF;

    -- The same subject under another issuer, or an unknown subject: nothing.
    PERFORM set_config('trust.reader_issuer', 'https://other.isolation.invalid', true);
    SELECT i.seen INTO seen FROM isolation_seen i;
    IF seen <> 'ca:- certificate:- audit:- scope:- san:- bounds:- profile:-' THEN
        RAISE EXCEPTION 'another issuer sees %', seen;
    END IF;
    PERFORM set_config('trust.reader_issuer', 'https://issuer.isolation.invalid', true),
            set_config('trust.reader_subject', 'nobody', true);
    SELECT i.seen INTO seen FROM isolation_seen i;
    IF seen <> 'ca:- certificate:- audit:- scope:- san:- bounds:- profile:-' THEN
        RAISE EXCEPTION 'a principal without grants sees %', seen;
    END IF;

    -- A predicate that names the other authority still reads nothing of it,
    -- whatever its shape: the view's own filter runs first.
    PERFORM set_config('trust.reader_subject', 'p1', true);
    IF EXISTS (SELECT 1 FROM management_certificate WHERE ca_id = y)
       OR EXISTS (SELECT 1 FROM management_certificate WHERE lower(ca_id) = y)
       OR EXISTS (SELECT 1 FROM management_audit WHERE ca_id IN (x, y) AND ca_id = y)
       OR EXISTS (SELECT 1 FROM management_certificate_san WHERE san_dns = 'shared.lab.invalid' AND ca_id = y)
       OR EXISTS (SELECT 1 FROM management_history_bounds WHERE ca_id = y)
       OR EXISTS (SELECT 1 FROM management_profile_draft WHERE ca_id = y)
       OR EXISTS (SELECT 1 FROM management_reader_scope WHERE subject = 'p2') THEN
        RAISE EXCEPTION 'principal p1 reads authority Y';
    END IF;

    -- The marker the API checks at startup.
    IF management_reader_isolation_version() <> 1 THEN
        RAISE EXCEPTION 'unexpected isolation marker';
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: each management view shows only the declared principal''s authorities, and nothing without one'
