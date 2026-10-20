-- Disposable metadata only. Certificate DER is a schema sentinel, not a signed X.509 object.
-- Subject CNs below are explicitly synthetic display fixtures, not parsed certificate claims.
INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'Paged Lab CA', 'v1'),
    ('ffffffff-ffff-4fff-8fff-ffffffffffff', 'Hidden Lab CA', 'v1');
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.example.test', 'operator', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');

INSERT INTO certificate_request (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state)
SELECT ('11111111-1111-4111-8111-' || lpad(to_hex(n), 12, '0'))::uuid,
       'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'paged-' || n,
       decode(repeat('01', 32), 'hex'), 'pagination-fixture', 'v1', 'SIGNED'
FROM generate_series(1, 102) AS n;

INSERT INTO serial_reservation (ca_id, serial_der_content, request_id)
SELECT 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
       decode('01' || lpad(to_hex(n), 4, '0'), 'hex'),
       ('11111111-1111-4111-8111-' || lpad(to_hex(n), 12, '0'))::uuid
FROM generate_series(1, 102) AS n;

INSERT INTO certificate (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at, subject_cn)
SELECT 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
       decode('01' || lpad(to_hex(n), 4, '0'), 'hex'),
       ('11111111-1111-4111-8111-' || lpad(to_hex(n), 12, '0'))::uuid,
       decode(repeat('02', 32), 'hex'), decode('3000', 'hex'),
       '2026-10-01T12:00:00Z'::timestamptz,
       'paged-' || lpad(to_hex(n), 4, '0') || '.lab.invalid'
FROM generate_series(1, 102) AS n;

INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version, recorded_at)
SELECT ('33333333-3333-4333-8333-' || lpad(to_hex(n), 12, '0'))::uuid,
       'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'private-pagination-actor',
       'certificate.signed', 'allow', 'v1', '2026-10-01T12:00:00Z'::timestamptz
FROM generate_series(1, 102) AS n;

INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version, recorded_at)
VALUES ('44444444-4444-4444-8444-444444444444',
        'ffffffff-ffff-4fff-8fff-ffffffffffff', 'hidden-actor',
        'certificate.signed', 'allow', 'v1', '2026-10-01T12:00:00Z');
