-- Pre-0014 revocation rows in a disposable database, applied after
-- management_populated_upgrade_seed.sql. 0001 accepts any reason 0..10 on a
-- direct INSERT: serial 01 is a legacy keyCompromise revocation that 0014 must
-- preserve, serial 02 carries removeFromCRL (8), which 0014 must refuse.
INSERT INTO certificate_request (
    request_id, ca_id, idempotency_key, csr_sha256,
    requester_id, policy_version, state
) VALUES (
    '22222222-2222-4222-8222-222222222222',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    'upgrade-legacy-hold-request', decode(repeat('04', 32), 'hex'),
    'lab-fixture', 'v1', 'SIGNED'
);

INSERT INTO serial_reservation (ca_id, request_id, serial_der_content) VALUES (
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    '22222222-2222-4222-8222-222222222222', decode('02', 'hex')
);

INSERT INTO certificate (
    ca_id, serial_der_content, request_id, fingerprint_sha256,
    certificate_der, signed_at
) VALUES (
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', decode('02', 'hex'),
    '22222222-2222-4222-8222-222222222222',
    decode(repeat('05', 32), 'hex'), decode('3000', 'hex'),
    '2026-10-02T12:00:00Z'
);

INSERT INTO revocation (
    ca_id, serial_der_content, reason_code, revoked_at, invalidity_at, actor_id
) VALUES
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', decode('01', 'hex'), 1,
     '2026-10-03T12:00:00Z', '2026-10-02T00:00:00Z', 'legacy-officer'),
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', decode('02', 'hex'), 8,
     '2026-10-03T13:00:00Z', NULL, 'legacy-officer');
