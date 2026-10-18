-- Pre-0012 fixture in a disposable database. The certificate bytes are a
-- schema-preservation sentinel, not a valid signed X.509 certificate.
INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'Existing Lab CA', 'v1'),
    ('ffffffff-ffff-4fff-8fff-ffffffffffff', 'Existing Hidden CA', 'v2');

INSERT INTO certificate_request (
    request_id, ca_id, idempotency_key, csr_sha256,
    requester_id, policy_version, state
) VALUES (
    '11111111-1111-4111-8111-111111111111',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    'upgrade-existing-request', decode(repeat('01', 32), 'hex'),
    'lab-fixture', 'v1', 'SIGNED'
);

INSERT INTO serial_reservation (ca_id, request_id, serial_der_content) VALUES (
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    '11111111-1111-4111-8111-111111111111', decode('01', 'hex')
);

INSERT INTO certificate (
    ca_id, serial_der_content, request_id, fingerprint_sha256,
    certificate_der, signed_at
) VALUES (
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', decode('01', 'hex'),
    '11111111-1111-4111-8111-111111111111',
    decode(repeat('02', 32), 'hex'), decode('3000', 'hex'),
    '2026-10-01T12:00:00Z'
);

INSERT INTO audit_event (
    event_id, ca_id, request_id, actor_id, event_type, decision, policy_version
) VALUES (
    '33333333-3333-4333-8333-333333333333',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    '11111111-1111-4111-8111-111111111111',
    'existing-private-actor', 'certificate.signed', 'allow', 'v1'
);
